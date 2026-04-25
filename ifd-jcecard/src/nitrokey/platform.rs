//! Host-side Trussed platform for the slot-1 Nitrokey card.
//!
//! The firmware's `runners/usbip` runs a full Trussed service over USB/IP.
//! We reuse its `Platform`/`Store`/`Syscall` types (they require `&'static`
//! filesystems, which the in-tree `trussed::virt` does not provide) but drive
//! the service directly from our IFD handler instead of going through a USB
//! transport.
//!
//! Layout on disk (all under `~/.jcecard/slot-1/`):
//!   * `trussed-ifs.bin`  internal flash image (littlefs2)
//!   * `trussed-efs.bin`  external flash image
//!   * `trussed-vfs.bin`  volatile (RAM) — re-created on every boot
//!
//! Sizes match the NK3 LPC55 runner (512-byte blocks × 128 blocks = 64 KiB
//! per volume) so the on-disk layout is source-compatible with the real
//! firmware — same mount parameters, same file format.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use generic_array::typenum::{U512, U8};
use littlefs2::driver::Storage;
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2_core::{DynFilesystem, Error, Result};
use log::{debug, warn};

/// Per-volume storage size in bytes (64 KiB).
const VOLUME_SIZE: usize = 512 * 128;

/// On-disk littlefs image for one Trussed volume.
pub struct DiskStorage {
    path: PathBuf,
}

impl DiskStorage {
    pub fn open_or_create(path: PathBuf) -> std::io::Result<Self> {
        // Ensure the file exists and is exactly VOLUME_SIZE bytes.
        if !path.exists() {
            let f = File::create(&path)?;
            f.set_len(VOLUME_SIZE as u64)?;
        } else {
            let f = File::open(&path)?;
            let len = f.metadata()?.len();
            if len != VOLUME_SIZE as u64 {
                warn!(
                    "Resizing Trussed volume {:?} ({} -> {} bytes)",
                    path, len, VOLUME_SIZE
                );
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(VOLUME_SIZE as u64)?;
            }
        }
        Ok(Self { path })
    }
}

impl Storage for DiskStorage {
    const READ_SIZE: usize = 16;
    const WRITE_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 512;
    const BLOCK_COUNT: usize = 128;
    const BLOCK_CYCLES: isize = -1;
    type CACHE_SIZE = U512;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
        debug!("[slot1 lfs] read {:?} offset={} len={}", self.path, offset, buffer.len());
        let mut f = File::open(&self.path).map_err(io_err)?;
        f.seek(SeekFrom::Start(offset as u64)).map_err(io_err)?;
        f.read(buffer).map_err(io_err)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        debug!("[slot1 lfs] write {:?} offset={} len={}", self.path, offset, data.len());
        if offset + data.len() > VOLUME_SIZE {
            return Err(Error::NO_SPACE);
        }
        let mut f = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(io_err)?;
        f.seek(SeekFrom::Start(offset as u64)).map_err(io_err)?;
        let n = f.write(data).map_err(io_err)?;
        f.flush().map_err(io_err)?;
        Ok(n)
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
        debug!("[slot1 lfs] erase {:?} offset={} len={}", self.path, offset, len);
        if offset + len > VOLUME_SIZE {
            return Err(Error::NO_SPACE);
        }
        let mut f = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(io_err)?;
        f.seek(SeekFrom::Start(offset as u64)).map_err(io_err)?;
        let ones = [0xFFu8; Self::BLOCK_SIZE];
        for _ in 0..(len / Self::BLOCK_SIZE) {
            f.write_all(&ones).map_err(io_err)?;
        }
        f.flush().map_err(io_err)?;
        Ok(len)
    }
}

fn io_err(_: std::io::Error) -> Error {
    Error::IO
}

/// A RAM-backed volatile storage (re-created every boot).
pub struct RamStorage {
    buf: Vec<u8>,
}

impl RamStorage {
    pub fn new() -> Self {
        Self {
            buf: vec![0xFF; VOLUME_SIZE],
        }
    }
}

impl Default for RamStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for RamStorage {
    const READ_SIZE: usize = 16;
    const WRITE_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 512;
    const BLOCK_COUNT: usize = 128;
    const BLOCK_CYCLES: isize = -1;
    type CACHE_SIZE = U512;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
        if offset + buffer.len() > VOLUME_SIZE {
            return Err(Error::NO_SPACE);
        }
        buffer.copy_from_slice(&self.buf[offset..offset + buffer.len()]);
        Ok(buffer.len())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        if offset + data.len() > VOLUME_SIZE {
            return Err(Error::NO_SPACE);
        }
        self.buf[offset..offset + data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
        if offset + len > VOLUME_SIZE {
            return Err(Error::NO_SPACE);
        }
        for b in &mut self.buf[offset..offset + len] {
            *b = 0xFF;
        }
        Ok(len)
    }
}

/// Mount (or format + mount) a storage into a leaked `&'static dyn DynFilesystem`.
///
/// `trussed_usbip::Store` requires static refs so the apps/Runner chain can
/// Clone + 'static. We leak the backing boxes — one-time cost per card.
fn leak_fs<S: Storage + Send + 'static>(
    mut storage: S,
    format: bool,
) -> std::result::Result<&'static dyn DynFilesystem, String> {
    let alloc: &'static mut Allocation<S> = Box::leak(Box::new(Filesystem::allocate()));
    if format {
        Filesystem::format(&mut storage)
            .map_err(|e| format!("littlefs format failed: {:?}", e))?;
    }
    let storage: &'static mut S = Box::leak(Box::new(storage));
    let fs: Filesystem<'static, S> = Filesystem::mount(alloc, storage)
        .map_err(|e| format!("littlefs mount failed: {:?}", e))?;
    let fs: &'static Filesystem<'static, S> = Box::leak(Box::new(fs));
    Ok(fs)
}

/// Build a static-lifetime `trussed_usbip::Store` backed by on-disk littlefs
/// images under `~/.jcecard/slot-1/`. Returns an `Err` (not a panic) on any
/// failure so pcscd survives slot-1 init problems and falls back to slot 0.
pub fn build_store() -> std::result::Result<trussed_usbip::Store, String> {
    let dir = super::storage::ensure_slot1_dir()
        .map_err(|e| format!("create slot-1 dir: {}", e))?;

    let ifs_path = dir.join("trussed-ifs.bin");
    let efs_path = dir.join("trussed-efs.bin");

    let ifs_new = !ifs_path.exists();
    let efs_new = !efs_path.exists();

    let ifs_backing =
        DiskStorage::open_or_create(ifs_path).map_err(|e| format!("open ifs: {}", e))?;
    let efs_backing =
        DiskStorage::open_or_create(efs_path).map_err(|e| format!("open efs: {}", e))?;
    let vfs_backing = RamStorage::new();

    Ok(trussed_usbip::Store {
        ifs: leak_fs(ifs_backing, ifs_new)?,
        efs: leak_fs(efs_backing, efs_new)?,
        vfs: leak_fs(vfs_backing, true)?,
    })
}
