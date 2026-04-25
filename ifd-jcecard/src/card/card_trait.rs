//! Generic `Card` trait used by the IFD handler to drive each slot.
//!
//! Slot 0 is the hand-rolled jcecard (`VirtualCard` in lib.rs); slot 1 is the
//! Nitrokey-backed card built on top of Trussed + apdu-dispatch. Both plug in
//! through this trait so lib.rs's IFDH* entry points do not have to know which
//! flavour they are talking to.

pub trait Card: Send {
    /// Power the card on and return the ATR.
    fn power_on(&mut self) -> Vec<u8>;

    /// Power the card off.
    fn power_off(&mut self);

    /// Warm-reset the card and return the new ATR.
    fn reset(&mut self) -> Vec<u8>;

    /// Process a single APDU and return the raw response (data || SW1 SW2).
    fn transmit_apdu(&mut self, apdu: &[u8]) -> Vec<u8>;

    /// Whether the card is currently powered.
    fn is_powered(&self) -> bool;

    /// Borrow the current ATR.
    fn atr(&self) -> &[u8];
}
