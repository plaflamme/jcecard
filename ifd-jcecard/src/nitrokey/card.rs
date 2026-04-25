//! `NitrokeyCard` — slot-1 card backed by the real upstream Nitrokey 3 stack.
//!
//! Architecture
//! ------------
//!
//! ```text
//!                  IFD handler thread
//!                  ──────────────────
//!                  NitrokeyCard::transmit_apdu
//!                      │  push APDU into contact interchange
//!                      ▼
//!                  ApduDispatch::poll(&mut [admin, oath, opcard, piv, …])
//!                      │  applets issue Trussed client syscalls
//!                      ▼
//!                  Syscall ──mpsc::Sender<()>──► service_thread
//!                                                ──────────────
//!                                                Service::process(&mut endpoints)
//! ```
//!
//! The Trussed `Service` runs on a dedicated background thread. When an
//! applet syscalls, our `Syscall` pings the service via mpsc; the service
//! drains its pipe and sends the response back through an interchange, so
//! the applet's sync-looking call returns. This mirrors the pattern used by
//! `trussed::virt` / `pc-usbip-runner`.
//!
//! APDU transport is an `apdu-dispatch` interchange channel: `transmit_apdu`
//! pushes a request into the `Requester`, calls `ApduDispatch::poll()` in a
//! loop until a response appears, then returns it.

use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use apdu_dispatch::dispatch::ApduDispatch;
use apdu_dispatch::interchanges::{
    Channel as ApduChannel, Data as ApduData, Requester as ApduRequester,
};
use apps::{AdminData, Apps, ClientBuilder, Data, Dispatch, Endpoints, FidoData, Variant};
use trussed::service::Service;
use trussed::types::Location;
use trussed::Bytes;
use utils::Version;

use crate::card::Card;

use super::atr::NITROKEY3_ATR;
use super::platform;

/// Virtual firmware version reported through admin-app.
const VIRTUAL_VERSION: Version = Version::new(1, 8, 3);
const VIRTUAL_VERSION_STRING: &str = "jcecard-nk3 1.8.3";

/// Fixed 128-bit UUID / serial. First byte 0x4E is ASCII 'N' so a human
/// reading the serial can recognise the virtual device.
const VIRTUAL_UUID: [u8; 16] = [
    0x4E, 0x4B, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF,
    0x4A, 0x43, 0x45, 0x43, 0x41, 0x52, 0x44, 0x31,
];

/// Maximum milliseconds we poll the dispatch loop waiting for a response
/// before giving up and returning SW=6400.
const APDU_TIMEOUT_MS: u64 = 2000;

// ---------------------------------------------------------------------------
// Runner wiring
// ---------------------------------------------------------------------------

/// Sync-over-mpsc Syscall. `trussed_usbip::Syscall` exists but doesn't
/// expose a constructor outside its own crate, so we roll a tiny equivalent
/// that wraps an mpsc Sender into the service thread.
#[derive(Clone)]
pub struct DesktopSyscall(std::sync::mpsc::Sender<()>);

impl trussed::platform::Syscall for DesktopSyscall {
    fn syscall(&mut self) {
        // If the service thread has exited (receiver dropped), the card is
        // effectively dead — we let the applet observe a request timeout.
        let _ = self.0.send(());
    }
}

/// A `Runner` implementation that feeds the `apps::Apps` orchestrator the
/// desktop-side Syscall + Store types.
#[derive(Clone)]
pub struct DesktopRunner;

impl apps::Runner for DesktopRunner {
    type Syscall = DesktopSyscall;
    type Reboot = NoReboot;
    type Store = trussed_usbip::Store;
    type Twi = ();
    type Se050Timer = ();

    fn uuid(&self) -> [u8; 16] {
        VIRTUAL_UUID
    }

    fn is_efs_available(&self) -> bool {
        true
    }
}

/// Reboot hooks — virtual card never actually reboots, so we panic loudly
/// rather than no-op to surface unexpected flows during testing.
pub struct NoReboot;

impl admin_app::Reboot for NoReboot {
    fn reboot() -> ! {
        panic!("[slot 1] admin-app reboot requested on virtual card");
    }
    fn reboot_to_firmware_update() -> ! {
        panic!("[slot 1] admin-app reboot-to-update requested on virtual card");
    }
    fn reboot_to_firmware_update_destructive() -> ! {
        panic!("[slot 1] admin-app reboot-to-update-destructive requested on virtual card");
    }
    fn locked() -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Driver — owns apps + dispatch + interchange requester on the IFD thread.
// ---------------------------------------------------------------------------

struct Driver {
    apps: Apps<DesktopRunner>,
    dispatch: ApduDispatch<'static>,
    requester: ApduRequester<'static>,
}

impl Driver {
    /// Send one APDU, drive the dispatch loop, and return the response.
    fn run_apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        let data = match ApduData::from_slice(apdu) {
            Ok(d) => d,
            Err(_) => {
                warn!("[slot 1] APDU too large for dispatch buffer ({} B)", apdu.len());
                return vec![0x67, 0x00];
            }
        };
        // The Requester must not have an in-flight request when we send.
        let _ = self.requester.take_response();
        if self.requester.request(data).is_err() {
            warn!("[slot 1] apdu interchange was not idle");
            return vec![0x64, 0x00];
        }

        let deadline = Instant::now() + Duration::from_millis(APDU_TIMEOUT_MS);
        while Instant::now() < deadline {
            self.apps.apdu_dispatch(|apps_slice| {
                self.dispatch.poll(apps_slice);
            });
            if let Some(resp) = self.requester.take_response() {
                return resp.into_iter().collect();
            }
            thread::sleep(Duration::from_millis(2));
        }
        warn!("[slot 1] APDU dispatch timed out after {} ms", APDU_TIMEOUT_MS);
        vec![0x64, 0x00]
    }
}

// ---------------------------------------------------------------------------
// NitrokeyCard
// ---------------------------------------------------------------------------

pub struct NitrokeyCard {
    atr: Vec<u8>,
    powered: bool,
    driver: Driver,

    /// Dropped to ask the service thread to stop, then join on drop.
    stop_tx: Option<Sender<()>>,
    service_thread: Option<thread::JoinHandle<()>>,
}

impl NitrokeyCard {
    pub fn new() -> Result<Self, String> {
        info!("[slot 1] Bootstrapping Nitrokey Trussed stack");

        // 1. On-disk littlefs-backed Trussed store. Propagate errors (no
        //    panic) so pcscd survives and can still expose slot 0 even if
        //    slot 1 cannot be initialised (e.g. storage dir not writable).
        let store = platform::build_store()?;

        // 2. Host-side Trussed platform (store + auto-confirm UI + ChaCha8 RNG).
        let platform = trussed_usbip::Platform::new(store);

        // 3. Dispatch with a fixed virtual "hardware" key — the upstream
        //    admin-app derives encrypted-blob keys from this plus per-client
        //    material, so consistency across restarts matters.
        // Dispatch's hardware-key capacity is `MAX_HW_KEY_LEN = 64` bytes
        // (see trussed-auth-backend). We use a fixed 16-byte virtual key.
        let hw_key: Bytes<64> = Bytes::try_from(&b"jcecard-nk3-hwkey"[..16])
            .expect("16 bytes fits a 64-byte Bytes");
        let dispatch = Dispatch::with_hw_key(Location::Internal, hw_key);

        // 4. Trussed service.
        let mut service = Service::with_dispatch(platform, dispatch);

        // 5. Syscall channel — main-thread clients ping the service thread.
        let (syscall_tx, syscall_rx) = mpsc::channel::<()>();
        let syscall = DesktopSyscall(syscall_tx);

        // 6. Build Apps.
        let runner = DesktopRunner;
        let mut client_builder = ClientBuilder::new(syscall);
        let data: Data<DesktopRunner> = Data {
            admin: AdminData::new(store, Variant::Usbip, VIRTUAL_VERSION, VIRTUAL_VERSION_STRING),
            fido: FidoData {
                has_nfc: false,
                max_message_size: 7609,
            },
            _marker: core::marker::PhantomData,
        };
        let apps: Apps<DesktopRunner> =
            Apps::new(&runner, &mut service, &mut client_builder, data);
        let endpoints: Endpoints = client_builder.into_endpoints();

        // 7. APDU-dispatch interchange channels. Leaked to get 'static.
        let contact_channel: &'static ApduChannel = Box::leak(Box::new(ApduChannel::new()));
        let contactless_channel: &'static ApduChannel = Box::leak(Box::new(ApduChannel::new()));
        let (contact_req, contact_resp) = contact_channel
            .split()
            .expect("contact channel split");
        let (_contactless_req, contactless_resp) = contactless_channel
            .split()
            .expect("contactless channel split");
        let dispatch = ApduDispatch::new(contact_resp, contactless_resp);

        // 8. Spawn Trussed service thread.
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let service_thread = thread::Builder::new()
            .name("nk3-trussed-svc".into())
            .spawn(move || {
                let mut service = service;
                let mut endpoints = endpoints;
                loop {
                    if stop_rx.try_recv().is_ok() {
                        info!("[slot 1] Trussed service thread exiting");
                        break;
                    }
                    if syscall_rx.recv_timeout(Duration::from_millis(25)).is_ok() {
                        service.process(&mut endpoints);
                    }
                }
            })
            .map_err(|e| format!("spawn trussed service thread: {}", e))?;

        Ok(Self {
            atr: NITROKEY3_ATR.to_vec(),
            powered: false,
            driver: Driver {
                apps,
                dispatch,
                requester: contact_req,
            },
            stop_tx: Some(stop_tx),
            service_thread: Some(service_thread),
        })
    }
}

impl Drop for NitrokeyCard {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.service_thread.take() {
            let _ = t.join();
        }
    }
}

impl Card for NitrokeyCard {
    fn power_on(&mut self) -> Vec<u8> {
        self.powered = true;
        info!("[slot 1] Nitrokey card powered on");
        self.atr.clone()
    }

    fn power_off(&mut self) {
        self.powered = false;
        info!("[slot 1] Nitrokey card powered off");
    }

    fn reset(&mut self) -> Vec<u8> {
        self.powered = true;
        info!("[slot 1] Nitrokey card reset");
        self.atr.clone()
    }

    fn transmit_apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        if !self.powered {
            return vec![0x69, 0x85];
        }
        debug!("[slot 1] APDU len={}", apdu.len());
        self.driver.run_apdu(apdu)
    }

    fn is_powered(&self) -> bool {
        self.powered
    }

    fn atr(&self) -> &[u8] {
        &self.atr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the card-using tests because the on-disk Trussed store is
    /// shared across them and concurrent access would corrupt littlefs.
    static CARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fresh_slot1_env() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
        let guard = CARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("JCECARD_STORAGE_DIR", dir.path());
        (dir, guard)
    }

    #[test]
    fn boots_and_exposes_nitrokey_atr() {
        let (_tmp, _lock) = fresh_slot1_env();
        let mut card = NitrokeyCard::new().expect("NitrokeyCard::new failed");
        let atr = card.power_on();
        assert_eq!(atr, NITROKEY3_ATR);
    }

    #[test]
    fn admin_app_version_apdu_roundtrip() {
        let (_tmp, _lock) = fresh_slot1_env();
        let mut card = NitrokeyCard::new().expect("NitrokeyCard::new failed");
        card.power_on();

        // SELECT admin-app: AID A0 00 00 08 47 00 00 00 01.
        let aid = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01];
        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        sel.extend_from_slice(&aid);
        let r = card.transmit_apdu(&sel);
        assert!(
            r.ends_with(&[0x90, 0x00]),
            "admin-app SELECT did not return 9000, got {:02X?}",
            r
        );

        // admin-app version INS (0x61) with an Le byte asking for the 4-byte
        // response. The upstream admin-app returns the firmware version.
        let ver = card.transmit_apdu(&[0x00, 0x61, 0x00, 0x00, 0x00]);
        assert!(
            ver.ends_with(&[0x90, 0x00]),
            "admin version did not return 9000, got {:02X?}",
            ver
        );
        // Real admin-app replies with 4 version bytes + SW; allow any body
        // as long as SW=9000 so we don't break on minor upstream changes.
        assert!(ver.len() >= 2);
    }
}
