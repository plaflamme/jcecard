//! Card data structures and storage
//!
//! This module contains the card state structures that match the Python
//! JSON format for backward compatibility.

pub mod state;
pub mod storage;
pub mod atr;
pub mod card_trait;

pub use state::{
    CardState, CardholderData, KeySlot, PINData, AlgorithmAttributes,
    AlgorithmID, CurveOID,
};
pub use storage::CardDataStore;
pub use atr::{DEFAULT_ATR, build_atr};
pub use card_trait::Card;
