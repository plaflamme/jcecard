//! Slot-1 Nitrokey 3 virtual card.
//!
//! Built on the upstream Trussed stack from `nitrokey-3-firmware` — the real
//! `admin-app`, `opcard`, `piv-authenticator`, and `secrets-app` crates wired
//! through `apdu-dispatch` on a host-side Trussed platform. Slot-1 state
//! persists to three littlefs images under `~/.jcecard/slot-1/`.

pub mod atr;
pub mod card;
pub mod platform;
pub mod storage;

pub use atr::NITROKEY3_ATR;
pub use card::NitrokeyCard;
