//! Slot-1 storage layout: `~/.jcecard/slot-1/<file>.json`.
//!
//! We reuse `CardDataStore::get_slot_storage_dir(1)` via a small helper here
//! so the admin-app and OATH modules do not have to know about the
//! `card::storage` internals.

use std::path::PathBuf;

/// Root directory for slot-1 persistent state.
pub fn slot1_dir() -> PathBuf {
    // Mirror CardDataStore::get_slot_storage_dir(1) without exposing it as pub.
    if let Ok(path) = std::env::var("JCECARD_STORAGE_DIR") {
        return PathBuf::from(path).join("slot-1");
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".jcecard").join("slot-1");
    }
    PathBuf::from("/var/lib/jcecard/slot-1")
}

/// Ensure the slot-1 directory exists (0o755).
pub fn ensure_slot1_dir() -> std::io::Result<PathBuf> {
    let dir = slot1_dir();
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
    Ok(dir)
}
