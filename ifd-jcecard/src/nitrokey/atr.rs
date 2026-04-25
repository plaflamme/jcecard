//! ATR for the slot-1 Nitrokey-backed virtual card.
//!
//! pynitrokey identifies a Nitrokey 3 **exclusively by exact ATR byte
//! equality** (see `pynitrokey/nk3/piv_app.py:73`). The historical bytes
//! literally spell "Nitrokey" in ASCII. Do not change these bytes — any
//! deviation causes `nitropy nk3 …` to skip the reader.

/// The Nitrokey 3 CCID ATR.
///
/// ```text
/// 3B 8F 01 80                                  ; TS + T0 (15 hist bytes) + TD1 (T=1)
/// 5D                                           ; compact-TLV tag: pre-issuing data
/// 4E 69 74 72 6F 6B 65 79                      ; "Nitrokey"
/// 00 00 00 00 00                               ; padding
/// 6A                                           ; TCK (XOR of all bytes from T0)
/// ```
pub const NITROKEY3_ATR: &[u8] = &[
    0x3B, 0x8F, 0x01, 0x80,
    0x5D,
    0x4E, 0x69, 0x74, 0x72, 0x6F, 0x6B, 0x65, 0x79,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x6A,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atr_is_exactly_19_bytes() {
        assert_eq!(NITROKEY3_ATR.len(), 19);
    }

    #[test]
    fn atr_tck_matches() {
        // T=1 ATR check byte: XOR of bytes from T0 through the last historical byte.
        let tck = NITROKEY3_ATR[1..NITROKEY3_ATR.len() - 1]
            .iter()
            .fold(0u8, |a, b| a ^ b);
        assert_eq!(tck, NITROKEY3_ATR[NITROKEY3_ATR.len() - 1]);
    }

    #[test]
    fn atr_contains_nitrokey_literal() {
        let s = &NITROKEY3_ATR[5..13];
        assert_eq!(s, b"Nitrokey");
    }
}
