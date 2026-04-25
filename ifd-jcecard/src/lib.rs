//! IFD Handler for jcecard virtual OpenPGP/PIV card
//!
//! This is a PC/SC IFD (Interface Device) handler that implements a virtual
//! smart card reader with embedded OpenPGP and PIV applets.
//!
//! The virtual card supports:
//! - OpenPGP card specification (ISO/IEC 7816-4/8)
//! - PIV card specification (NIST SP 800-73-4)

#![allow(dead_code)]
// Allow raw pointer dereference in extern "C" functions - required for PC/SC IFD API
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// Allow uppercase acronyms for Windows API type names (DWORD, LPSTR, etc.)
#![allow(clippy::upper_case_acronyms)]

// Core modules
pub mod apdu;
pub mod tlv;
pub mod card;
pub mod crypto;
pub mod openpgp;
pub mod piv;

#[cfg(feature = "nitrokey")]
pub mod nitrokey;

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::ffi::{c_char, c_uchar, c_ulong, CStr};
use std::ptr;
use std::sync::Arc;
use log::{debug, info, error};

use apdu::{parse_apdu, Response};
use card::{atr, Card, CardDataStore};
use openpgp::OpenPGPApplet;
use openpgp::applet::OPENPGP_AID_PREFIX;
use piv::{PIVApplet, applet::PIV_AID};

/// Number of virtual card slots this IFD handler exposes. Slot 0 is the
/// hand-rolled jcecard, slot 1 is the Nitrokey-backed card.
const NUM_SLOTS: usize = 2;

// PC/SC lite types
type DWORD = c_ulong;
type PDWORD = *mut DWORD;
type PUCHAR = *mut c_uchar;
type LPSTR = *const c_char;
type RESPONSECODE = c_ulong;
type UCHAR = c_uchar;

// Response codes
const IFD_SUCCESS: RESPONSECODE = 0;
const IFD_ERROR_TAG: RESPONSECODE = 600;
const IFD_ERROR_NOT_SUPPORTED: RESPONSECODE = 606;
const IFD_COMMUNICATION_ERROR: RESPONSECODE = 612;
const IFD_ICC_PRESENT: RESPONSECODE = 615;
const IFD_ICC_NOT_PRESENT: RESPONSECODE = 614;

// Tags for GetCapabilities
const TAG_IFD_ATR: DWORD = 0x0303;
const TAG_IFD_SLOTS_NUMBER: DWORD = 0x0FAE;
const TAG_IFD_THREAD_SAFE: DWORD = 0x0FAD;
const TAG_IFD_SLOT_THREAD_SAFE: DWORD = 0x0FBE;

// Power actions
const IFD_POWER_UP: DWORD = 500;
const IFD_POWER_DOWN: DWORD = 501;
const IFD_RESET: DWORD = 502;

// SCARD_IO_HEADER structure (simplified)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_IO_HEADER {
    pub protocol: DWORD,
    pub length: DWORD,
}

// Maximum ATR size
const MAX_ATR_SIZE: usize = 33;

/// Active applet in the virtual card
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveApplet {
    None,
    OpenPGP,
    PIV,
}

/// Virtual card containing both OpenPGP and PIV applets
struct VirtualCard {
    /// OpenPGP applet
    openpgp: OpenPGPApplet,
    /// PIV applet
    piv: PIVApplet,
    /// Currently active applet
    active_applet: ActiveApplet,
    /// Card ATR
    atr: Vec<u8>,
    /// Whether the card is powered
    powered: bool,
}

impl VirtualCard {
    /// Create a new virtual card
    fn new() -> Self {
        // Slot-0 storage: ~/.jcecard/slot-0/card_state.json (with legacy migration).
        let mut store = CardDataStore::new_for_slot(None, 0);
        store.load();  // Load existing state or initialize defaults
        Self {
            openpgp: OpenPGPApplet::new(store),
            piv: PIVApplet::new(),
            active_applet: ActiveApplet::None,
            atr: atr::create_openpgp_atr(),
            powered: false,
        }
    }

    /// Process an APDU command
    fn process_apdu(&mut self, apdu_bytes: &[u8]) -> Vec<u8> {
        if !self.powered {
            // Return SW 6985 (Conditions not satisfied)
            return vec![0x69, 0x85];
        }

        // Parse APDU
        let cmd = match parse_apdu(apdu_bytes) {
            Ok(apdu) => apdu,
            Err(e) => {
                error!("Failed to parse APDU: {:?}", e);
                // Return SW 6700 (Wrong length)
                return vec![0x67, 0x00];
            }
        };

        debug!("Processing APDU: CLA={:02X} INS={:02X} P1={:02X} P2={:02X}",
               cmd.cla, cmd.ins, cmd.p1, cmd.p2);

        // Check for SELECT command
        if cmd.ins == 0xA4 {
            if cmd.p1 == 0x04 {
                // SELECT by DF name (AID) - route to applet selection
                return self.handle_select(&cmd);
            } else {
                // SELECT MF (P1=0x00) or other SELECT variants not supported
                // Real Yubikey returns INS_NOT_SUPPORTED for these
                return vec![0x6D, 0x00];
            }
        }

        // Route to active applet
        let response = match self.active_applet {
            ActiveApplet::OpenPGP => self.openpgp.process_apdu(&cmd),
            ActiveApplet::PIV => self.piv.process_apdu(&cmd),
            ActiveApplet::None => {
                // No applet selected - return SW 6985 (Conditions not satisfied)
                Response::error(apdu::SW::CONDITIONS_NOT_SATISFIED)
            }
        };

        // Convert response to bytes
        self.response_to_bytes(&response)
    }

    /// Handle SELECT command for applet routing
    fn handle_select(&mut self, cmd: &apdu::APDU) -> Vec<u8> {
        // Check if it's OpenPGP AID
        if cmd.data.starts_with(OPENPGP_AID_PREFIX) {
            self.active_applet = ActiveApplet::OpenPGP;
            info!("Selected OpenPGP applet");
            let response = self.openpgp.process_apdu(cmd);
            return self.response_to_bytes(&response);
        }

        // Check if it's PIV AID
        if cmd.data.starts_with(PIV_AID) {
            self.active_applet = ActiveApplet::PIV;
            info!("Selected PIV applet");
            let response = self.piv.process_apdu(cmd);
            return self.response_to_bytes(&response);
        }

        // Check if it's Yubikey Management AID (A0 00 00 05 27 47 11 17)
        // scdaemon queries this to get firmware version
        const YUBIKEY_MGMT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
        if cmd.data == YUBIKEY_MGMT_AID {
            info!("Selected Yubikey Management applet (returning version string)");
            // Return version 5.4.3 to indicate full OpenPGP 3.4 support
            let mut response: Vec<u8> = b"jcecard - FW version 5.4.3".to_vec();
            response.push(0x90);
            response.push(0x00);
            return response;
        }

        // Unknown AID - return SW 6A82 (File not found)
        debug!("Unknown AID: {:02X?}", cmd.data);
        vec![0x6A, 0x82]
    }

    /// Convert Response to raw bytes (data + SW1 + SW2)
    fn response_to_bytes(&self, response: &Response) -> Vec<u8> {
        let mut result = response.data.clone();
        result.push(response.sw1);
        result.push(response.sw2);
        result
    }
}

impl Card for VirtualCard {
    fn power_on(&mut self) -> Vec<u8> {
        self.powered = true;
        self.active_applet = ActiveApplet::None;
        info!("[slot 0] Virtual card powered on");
        self.atr.clone()
    }

    fn power_off(&mut self) {
        self.powered = false;
        self.active_applet = ActiveApplet::None;
        self.openpgp.reset();
        self.piv.reset();
        info!("[slot 0] Virtual card powered off");
    }

    fn reset(&mut self) -> Vec<u8> {
        self.openpgp.reset();
        self.piv.reset();
        self.active_applet = ActiveApplet::None;
        self.powered = true;
        info!("[slot 0] Virtual card reset");
        self.atr.clone()
    }

    fn transmit_apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.process_apdu(apdu)
    }

    fn is_powered(&self) -> bool {
        self.powered
    }

    fn atr(&self) -> &[u8] {
        &self.atr
    }
}

/// A boxed, mutex-guarded card that the IFD state holds per slot.
type SlotCard = Arc<Mutex<Box<dyn Card>>>;

/// Build the per-slot card for the given slot index.
fn build_slot_card(slot: usize) -> Option<Box<dyn Card>> {
    match slot {
        0 => Some(Box::new(VirtualCard::new())),
        #[cfg(feature = "nitrokey")]
        1 => match nitrokey::NitrokeyCard::new() {
            Ok(card) => Some(Box::new(card)),
            Err(e) => {
                log_error(&format!("Failed to initialise Nitrokey slot: {}", e));
                None
            }
        },
        _ => None,
    }
}

/// Global state for the IFD handler. Slot 0 = jcecard VirtualCard,
/// slot 1 = Nitrokey-backed card.
struct IfdState {
    slots: [Option<SlotCard>; NUM_SLOTS],
}

impl IfdState {
    fn new() -> Self {
        Self {
            slots: Default::default(),
        }
    }
}

// Global state
static IFD_STATE: OnceCell<Mutex<IfdState>> = OnceCell::new();

fn get_state() -> &'static Mutex<IfdState> {
    IFD_STATE.get_or_init(|| Mutex::new(IfdState::new()))
}

fn log_info(msg: &str) {
    // Use write_all + flush on a single allocated line so our output
    // doesn't interleave mid-line with pcscd's own stderr writes (which
    // produced log entries like "action=50000000044 pcscdaemon.c:…").
    use std::io::Write;
    let line = format!("[ifd-jcecard] {}\n", msg);
    let _ = std::io::stderr().write_all(line.as_bytes());
    let _ = std::io::stderr().flush();
}

fn log_error(msg: &str) {
    use std::io::Write;
    let line = format!("[ifd-jcecard] ERROR: {}\n", msg);
    let _ = std::io::stderr().write_all(line.as_bytes());
    let _ = std::io::stderr().flush();
}

// ============================================================================
// IFD Handler API Implementation
// ============================================================================

/// Create a communication channel to the reader
#[no_mangle]
pub extern "C" fn IFDHCreateChannelByName(lun: DWORD, device_name: LPSTR) -> RESPONSECODE {
    let name = if device_name.is_null() {
        "null".to_string()
    } else {
        unsafe { CStr::from_ptr(device_name) }
            .to_string_lossy()
            .to_string()
    };
    log_info(&format!("IFDHCreateChannelByName: LUN={}, device={}", lun, name));

    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        log_error(&format!("Invalid slot: {}", slot));
        return IFD_COMMUNICATION_ERROR;
    }

    match build_slot_card(slot) {
        Some(card) => {
            state.slots[slot] = Some(Arc::new(Mutex::new(card)));
            log_info(&format!("[slot {}] Channel created", slot));
            IFD_SUCCESS
        }
        None => {
            log_error(&format!("[slot {}] No card implementation for this slot", slot));
            IFD_COMMUNICATION_ERROR
        }
    }
}

/// Create a communication channel (legacy)
#[no_mangle]
pub extern "C" fn IFDHCreateChannel(lun: DWORD, channel: DWORD) -> RESPONSECODE {
    log_info(&format!("IFDHCreateChannel: LUN={}, channel={}", lun, channel));

    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        log_error(&format!("Invalid slot: {}", slot));
        return IFD_COMMUNICATION_ERROR;
    }

    match build_slot_card(slot) {
        Some(card) => {
            state.slots[slot] = Some(Arc::new(Mutex::new(card)));
            log_info(&format!("[slot {}] Channel created", slot));
            IFD_SUCCESS
        }
        None => {
            log_error(&format!("[slot {}] No card implementation for this slot", slot));
            IFD_COMMUNICATION_ERROR
        }
    }
}

/// Close the communication channel
#[no_mangle]
pub extern "C" fn IFDHCloseChannel(lun: DWORD) -> RESPONSECODE {
    log_info(&format!("IFDHCloseChannel: LUN={}", lun));

    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    if let Some(card_state) = state.slots[slot].take() {
        let mut cs = card_state.lock();
        cs.power_off();
    }

    IFD_SUCCESS
}

/// Get reader capabilities
#[no_mangle]
pub extern "C" fn IFDHGetCapabilities(
    lun: DWORD,
    tag: DWORD,
    length: PDWORD,
    value: PUCHAR,
) -> RESPONSECODE {
    log_info(&format!("IFDHGetCapabilities: LUN={}, tag=0x{:04X}", lun, tag));

    if length.is_null() {
        return IFD_COMMUNICATION_ERROR;
    }

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    match tag {
        TAG_IFD_ATR => {
            if slot >= state.slots.len() {
                return IFD_COMMUNICATION_ERROR;
            }

            if let Some(ref card_arc) = state.slots[slot] {
                let card = card_arc.lock();
                if card.is_powered() {
                    let atr = card.atr();
                    let atr_len = atr.len().min(MAX_ATR_SIZE);
                    unsafe {
                        *length = atr_len as DWORD;
                        if !value.is_null() {
                            ptr::copy_nonoverlapping(atr.as_ptr(), value, atr_len);
                        }
                    }
                    return IFD_SUCCESS;
                }
            }
            IFD_ICC_NOT_PRESENT
        }
        TAG_IFD_SLOTS_NUMBER => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = NUM_SLOTS as UCHAR;
                }
            }
            IFD_SUCCESS
        }
        TAG_IFD_THREAD_SAFE => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = 0; // Not thread safe at IFD level
                }
            }
            IFD_SUCCESS
        }
        TAG_IFD_SLOT_THREAD_SAFE => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = 1; // Slot level is thread safe
                }
            }
            IFD_SUCCESS
        }
        _ => {
            log_info(&format!("Unknown tag: 0x{:04X}", tag));
            IFD_ERROR_TAG
        }
    }
}

/// Set reader capabilities (not supported)
#[no_mangle]
pub extern "C" fn IFDHSetCapabilities(
    _lun: DWORD,
    _tag: DWORD,
    _length: DWORD,
    _value: PUCHAR,
) -> RESPONSECODE {
    IFD_ERROR_NOT_SUPPORTED
}

/// Set protocol parameters (minimal implementation)
#[no_mangle]
pub extern "C" fn IFDHSetProtocolParameters(
    lun: DWORD,
    protocol: DWORD,
    _flags: UCHAR,
    _pts1: UCHAR,
    _pts2: UCHAR,
    _pts3: UCHAR,
) -> RESPONSECODE {
    log_info(&format!(
        "IFDHSetProtocolParameters: LUN={}, protocol={}",
        lun, protocol
    ));
    IFD_SUCCESS
}

/// Power the ICC (Integrated Circuit Card)
#[no_mangle]
pub extern "C" fn IFDHPowerICC(
    lun: DWORD,
    action: DWORD,
    atr: PUCHAR,
    atr_length: PDWORD,
) -> RESPONSECODE {
    log_info(&format!("IFDHPowerICC: LUN={}, action={}", lun, action));

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    let card_arc = match &state.slots[slot] {
        Some(arc) => arc.clone(),
        None => return IFD_COMMUNICATION_ERROR,
    };
    drop(state); // Release state lock before card operations

    let mut card = card_arc.lock();

    match action {
        IFD_POWER_UP => {
            log_info(&format!("[slot {}] Powering up", slot));
            let card_atr = card.power_on();
            log_info(&format!(
                "[slot {}] Powered on, ATR length: {}",
                slot,
                card_atr.len()
            ));
            if !atr.is_null() && !atr_length.is_null() {
                let copy_len = card_atr.len().min(MAX_ATR_SIZE);
                unsafe {
                    ptr::copy_nonoverlapping(card_atr.as_ptr(), atr, copy_len);
                    *atr_length = copy_len as DWORD;
                }
            }
            IFD_SUCCESS
        }
        IFD_POWER_DOWN => {
            log_info(&format!("[slot {}] Powering down", slot));
            card.power_off();
            IFD_SUCCESS
        }
        IFD_RESET => {
            log_info(&format!("[slot {}] Resetting", slot));
            let card_atr = card.reset();
            log_info(&format!(
                "[slot {}] Reset, ATR length: {}",
                slot,
                card_atr.len()
            ));
            if !atr.is_null() && !atr_length.is_null() {
                let copy_len = card_atr.len().min(MAX_ATR_SIZE);
                unsafe {
                    ptr::copy_nonoverlapping(card_atr.as_ptr(), atr, copy_len);
                    *atr_length = copy_len as DWORD;
                }
            }
            IFD_SUCCESS
        }
        _ => {
            log_error(&format!("Unknown power action: {}", action));
            IFD_ERROR_NOT_SUPPORTED
        }
    }
}

/// Transmit data to the ICC
#[no_mangle]
pub extern "C" fn IFDHTransmitToICC(
    lun: DWORD,
    send_pci: SCARD_IO_HEADER,
    tx_buffer: PUCHAR,
    tx_length: DWORD,
    rx_buffer: PUCHAR,
    rx_length: PDWORD,
    _recv_pci: *mut SCARD_IO_HEADER,
) -> RESPONSECODE {
    log_info(&format!(
        "IFDHTransmitToICC: LUN={}, protocol={}, tx_len={}",
        lun, send_pci.protocol, tx_length
    ));

    if tx_buffer.is_null() || rx_buffer.is_null() || rx_length.is_null() {
        return IFD_COMMUNICATION_ERROR;
    }

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    let card_arc = match &state.slots[slot] {
        Some(arc) => arc.clone(),
        None => return IFD_COMMUNICATION_ERROR,
    };
    drop(state);

    // Build APDU from tx_buffer
    let apdu = unsafe { std::slice::from_raw_parts(tx_buffer, tx_length as usize) };
    log_info(&format!("APDU: {:02X?}", apdu));

    let mut card = card_arc.lock();
    let response = card.transmit_apdu(apdu);

    log_info(&format!("Response: {:02X?}", response));
    let max_len = unsafe { *rx_length } as usize;
    let copy_len = response.len().min(max_len);
    unsafe {
        ptr::copy_nonoverlapping(response.as_ptr(), rx_buffer, copy_len);
        *rx_length = copy_len as DWORD;
    }
    IFD_SUCCESS
}

/// Check if ICC is present
#[no_mangle]
pub extern "C" fn IFDHICCPresence(lun: DWORD) -> RESPONSECODE {
    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_ICC_NOT_PRESENT;
    }

    // Virtual card is always present
    if state.slots[slot].is_some() {
        return IFD_ICC_PRESENT;
    }

    IFD_ICC_NOT_PRESENT
}

/// Control the reader (not supported)
#[no_mangle]
pub extern "C" fn IFDHControl(
    _lun: DWORD,
    _control_code: DWORD,
    _tx_buffer: PUCHAR,
    _tx_length: DWORD,
    _rx_buffer: PUCHAR,
    _rx_length: DWORD,
    _bytes_returned: PDWORD,
) -> RESPONSECODE {
    IFD_ERROR_NOT_SUPPORTED
}
