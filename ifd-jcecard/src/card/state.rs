//! Card state data structures
//!
//! These structures match the Python JSON format for backward compatibility.

use serde::{Deserialize, Serialize};

/// Custom serde module for base64 encoding of byte vectors
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if bytes.is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str(&STANDARD.encode(bytes))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Algorithm IDs for OpenPGP card
#[allow(dead_code)]
pub struct AlgorithmID;

#[allow(dead_code)]
impl AlgorithmID {
    pub const RSA: u8 = 0x01;
    pub const ECDH: u8 = 0x12;        // ECDH (for NIST curves and X25519)
    pub const ECDSA: u8 = 0x13;       // ECDSA (for NIST curves)
    pub const EDDSA: u8 = 0x16;       // EdDSA (Ed25519)
    // Legacy aliases
    pub const ECDSA_P256: u8 = 0x13;
    pub const ECDH_X25519: u8 = 0x12;
}

/// Curve OIDs
#[allow(dead_code)]
pub struct CurveOID;

#[allow(dead_code)]
impl CurveOID {
    pub const NIST_P256: &'static [u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    pub const NIST_P384: &'static [u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    pub const NIST_P521: &'static [u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
    pub const SECP256K1: &'static [u8] = &[0x2B, 0x81, 0x04, 0x00, 0x0A];
    pub const ED25519: &'static [u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    pub const X25519: &'static [u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

    /// Check if OID matches a known curve and return a descriptive name
    pub fn name(oid: &[u8]) -> Option<&'static str> {
        if oid == Self::NIST_P256 {
            Some("nistp256")
        } else if oid == Self::NIST_P384 {
            Some("nistp384")
        } else if oid == Self::NIST_P521 {
            Some("nistp521")
        } else if oid == Self::SECP256K1 {
            Some("secp256k1")
        } else if oid == Self::ED25519 {
            Some("ed25519")
        } else if oid == Self::X25519 {
            Some("cv25519")
        } else {
            None
        }
    }
}

/// Algorithm attributes for a key slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmAttributes {
    pub algorithm_id: u8,
    pub param1: u16,  // RSA modulus bits or 0 for ECC
    pub param2: u16,  // RSA exponent bits or 0 for ECC
    pub param3: u8,   // Import format
    #[serde(with = "base64_bytes")]
    pub curve_oid: Vec<u8>,
}

impl Default for AlgorithmAttributes {
    fn default() -> Self {
        Self::rsa(2048)
    }
}

impl AlgorithmAttributes {
    /// Create RSA algorithm attributes
    pub fn rsa(bits: u16) -> Self {
        Self {
            algorithm_id: AlgorithmID::RSA,
            param1: bits,
            param2: 32,  // exponent bits
            param3: 0,
            curve_oid: Vec::new(),
        }
    }

    /// Create Ed25519 algorithm attributes
    pub fn ed25519() -> Self {
        Self {
            algorithm_id: AlgorithmID::EDDSA,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::ED25519.to_vec(),
        }
    }

    /// Create X25519 algorithm attributes
    pub fn x25519() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDH,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::X25519.to_vec(),
        }
    }

    /// Create NIST P-256 ECDSA algorithm attributes (for signing)
    pub fn nistp256_ecdsa() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDSA,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P256.to_vec(),
        }
    }

    /// Create NIST P-256 ECDH algorithm attributes (for decryption)
    pub fn nistp256_ecdh() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDH,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P256.to_vec(),
        }
    }

    /// Create NIST P-384 ECDSA algorithm attributes (for signing)
    pub fn nistp384_ecdsa() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDSA,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P384.to_vec(),
        }
    }

    /// Create NIST P-384 ECDH algorithm attributes (for decryption)
    pub fn nistp384_ecdh() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDH,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P384.to_vec(),
        }
    }

    /// Create NIST P-521 ECDSA algorithm attributes (for signing)
    pub fn nistp521_ecdsa() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDSA,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P521.to_vec(),
        }
    }

    /// Create NIST P-521 ECDH algorithm attributes (for decryption)
    pub fn nistp521_ecdh() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDH,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::NIST_P521.to_vec(),
        }
    }

    /// Create secp256k1 ECDSA algorithm attributes (for signing)
    pub fn secp256k1_ecdsa() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDSA,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::SECP256K1.to_vec(),
        }
    }

    /// Create secp256k1 ECDH algorithm attributes (for decryption)
    pub fn secp256k1_ecdh() -> Self {
        Self {
            algorithm_id: AlgorithmID::ECDH,
            param1: 0,
            param2: 0,
            param3: 0,
            curve_oid: CurveOID::SECP256K1.to_vec(),
        }
    }

    /// Check if this is a NIST P-256 curve
    pub fn is_nistp256(&self) -> bool {
        self.curve_oid == CurveOID::NIST_P256
    }

    /// Check if this is a NIST P-384 curve
    pub fn is_nistp384(&self) -> bool {
        self.curve_oid == CurveOID::NIST_P384
    }

    /// Check if this is a NIST P-521 curve
    pub fn is_nistp521(&self) -> bool {
        self.curve_oid == CurveOID::NIST_P521
    }

    /// Check if this is a secp256k1 curve
    pub fn is_secp256k1(&self) -> bool {
        self.curve_oid == CurveOID::SECP256K1
    }

    /// Check if this is an Ed25519 curve
    pub fn is_ed25519(&self) -> bool {
        self.curve_oid == CurveOID::ED25519
    }

    /// Check if this is an X25519 curve
    pub fn is_x25519(&self) -> bool {
        self.curve_oid == CurveOID::X25519
    }

    /// Encode to OpenPGP card format
    /// For RSA: algo_id || modulus_bits (2) || exponent_bits (2) || format (1)
    /// For ECC: algo_id || oid (NO length byte - length is implied by TLV wrapper)
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.algorithm_id == AlgorithmID::RSA {
            vec![
                self.algorithm_id,
                (self.param1 >> 8) as u8,
                self.param1 as u8,
                (self.param2 >> 8) as u8,
                self.param2 as u8,
                self.param3,
            ]
        } else {
            let mut result = vec![self.algorithm_id];
            // OID follows directly (no length byte - real Yubikey format)
            result.extend_from_slice(&self.curve_oid);
            result
        }
    }

    /// Parse from bytes
    /// For RSA: algo_id || modulus_bits (2) || exponent_bits (2) || format (1)
    /// For ECC: algo_id || oid (NO length byte - real Yubikey format)
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let algorithm_id = data[0];
        if algorithm_id == AlgorithmID::RSA {
            if data.len() >= 6 {
                Some(Self {
                    algorithm_id,
                    param1: ((data[1] as u16) << 8) | (data[2] as u16),
                    param2: ((data[3] as u16) << 8) | (data[4] as u16),
                    param3: data[5],
                    curve_oid: Vec::new(),
                })
            } else {
                None
            }
        } else if data.len() >= 2 {
            // ECC: algo_id || oid (OID is the rest of the data, no length byte)
            Some(Self {
                algorithm_id,
                param1: 0,
                param2: 0,
                param3: 0,
                curve_oid: data[1..].to_vec(),
            })
        } else {
            None
        }
    }
}

/// Data for a single key slot (SIG, DEC, or AUT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    #[serde(with = "base64_bytes")]
    pub fingerprint: Vec<u8>,
    pub generation_time: u32,
    #[serde(with = "base64_bytes")]
    pub ca_fingerprint: Vec<u8>,
    pub algorithm: AlgorithmAttributes,
    pub uif: u8,
    #[serde(with = "base64_bytes")]
    pub private_key_data: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub public_key_data: Vec<u8>,
}

impl Default for KeySlot {
    fn default() -> Self {
        Self {
            fingerprint: vec![0u8; 20],
            generation_time: 0,
            ca_fingerprint: vec![0u8; 20],
            algorithm: AlgorithmAttributes::default(),
            uif: 0,
            private_key_data: Vec::new(),
            public_key_data: Vec::new(),
        }
    }
}

impl KeySlot {
    /// Check if this slot has a key
    pub fn has_key(&self) -> bool {
        !self.fingerprint.iter().all(|&b| b == 0)
    }

    /// Get fingerprint padded to 20 bytes
    pub fn fingerprint_padded(&self) -> Vec<u8> {
        let mut fp = self.fingerprint.clone();
        fp.resize(20, 0);
        fp
    }

    /// Get CA fingerprint padded to 20 bytes
    pub fn ca_fingerprint_padded(&self) -> Vec<u8> {
        let mut fp = self.ca_fingerprint.clone();
        fp.resize(20, 0);
        fp
    }
}

/// PIN-related data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PINData {
    #[serde(with = "base64_bytes")]
    pub pw1_hash: Vec<u8>,
    pub pw1_length: u8,
    pub pw1_min_length: u8,
    pub pw1_max_length: u8,
    pub pw1_retry_counter: u8,
    pub pw1_max_retries: u8,
    pub pw1_valid_multiple: bool,

    #[serde(with = "base64_bytes")]
    pub pw3_hash: Vec<u8>,
    pub pw3_length: u8,
    pub pw3_min_length: u8,
    pub pw3_max_length: u8,
    pub pw3_retry_counter: u8,
    pub pw3_max_retries: u8,

    #[serde(with = "base64_bytes")]
    pub rc_hash: Vec<u8>,
    pub rc_length: u8,
    pub rc_min_length: u8,
    pub rc_max_length: u8,
    pub rc_retry_counter: u8,
    pub rc_max_retries: u8,
}

impl Default for PINData {
    fn default() -> Self {
        Self {
            pw1_hash: Vec::new(),
            pw1_length: 6,
            pw1_min_length: 6,
            pw1_max_length: 127,
            pw1_retry_counter: 3,
            pw1_max_retries: 3,
            pw1_valid_multiple: true,

            pw3_hash: Vec::new(),
            pw3_length: 8,
            pw3_min_length: 8,
            pw3_max_length: 127,
            pw3_retry_counter: 3,
            pw3_max_retries: 3,

            rc_hash: Vec::new(),
            rc_length: 0,
            rc_min_length: 8,
            rc_max_length: 127,
            rc_retry_counter: 0,
            rc_max_retries: 3,
        }
    }
}

/// Cardholder-related data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CardholderData {
    pub name: String,
    #[serde(default = "default_language")]
    pub language: String,
    pub sex: u8,
    pub login: String,
    pub url: String,
}

fn default_language() -> String {
    "en".to_string()
}

impl CardholderData {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            language: "en".to_string(),
            sex: 0,
            login: String::new(),
            url: String::new(),
        }
    }
}

/// Complete card state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardState {
    pub manufacturer_id: u16,
    pub serial_number: u32,
    pub version_major: u8,
    pub version_minor: u8,
    pub pin_data: PINData,
    pub cardholder: CardholderData,
    pub key_sig: KeySlot,
    pub key_dec: KeySlot,
    pub key_aut: KeySlot,
    pub signature_counter: u32,
    #[serde(with = "base64_bytes")]
    pub private_do_1: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub private_do_2: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub private_do_3: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub private_do_4: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub certificate: Vec<u8>,
    pub terminated: bool,
}

impl Default for CardState {
    fn default() -> Self {
        Self {
            manufacturer_id: 0x0000,
            serial_number: 0x00000001,
            version_major: 3,
            version_minor: 4,
            pin_data: PINData::default(),
            cardholder: CardholderData::new(),
            key_sig: KeySlot::default(),
            key_dec: KeySlot::default(),
            key_aut: KeySlot::default(),
            signature_counter: 0,
            private_do_1: Vec::new(),
            private_do_2: Vec::new(),
            private_do_3: Vec::new(),
            private_do_4: Vec::new(),
            certificate: Vec::new(),
            terminated: false,
        }
    }
}

impl CardState {
    /// Get the Application Identifier (AID)
    pub fn get_aid(&self) -> Vec<u8> {
        vec![
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,  // RID + PIX
            self.version_major, self.version_minor,
            (self.manufacturer_id >> 8) as u8,
            self.manufacturer_id as u8,
            (self.serial_number >> 24) as u8,
            (self.serial_number >> 16) as u8,
            (self.serial_number >> 8) as u8,
            self.serial_number as u8,
            0x00, 0x00,  // RFU
        ]
    }

    /// Get the historical bytes for ATR and 5F52 DO
    /// Format: Category indicator + compact-TLV objects + status indicator + SW
    pub fn get_historical_bytes(&self) -> Vec<u8> {
        // Match real Yubikey format: 00 73 00 00 E0 05 90 00
        let lifecycle_status = if self.terminated { 0x07 } else { 0x05 };
        vec![
            0x00,  // Category indicator: compact TLV
            0x73,  // Tag 7 (card capabilities), length 3
            0x00, 0x00, 0xE0,  // Card capabilities (matches real Yubikey)
            lifecycle_status,  // Status indicator byte
            0x90, 0x00,  // Status word
        ]
    }

    /// Get the General Feature Management DO (7F74)
    pub fn get_general_feature_management(&self) -> Vec<u8> {
        vec![0x81, 0x01, 0x20]
    }

    /// Get the Extended Capabilities DO (C0)
    pub fn get_extended_capabilities(&self) -> Vec<u8> {
        // Flags: get_challenge, key_import, pw_status_change, private_dos, algo_attr_change
        let flags: u8 = 0x40 | 0x20 | 0x10 | 0x08 | 0x04;
        vec![
            flags,
            0x00,  // SM algorithm (0 = none)
            0x00, 0xFF,  // max challenge length (255)
            0x08, 0x00,  // max cardholder cert length (2048)
            0x00, 0xFF,  // max special DO length (255)
            0x00,  // PIN block 2 format
            0x00,  // MSE command (0 = not supported, matches real Yubikey)
        ]
    }

    /// Get the PW Status Bytes (C4)
    pub fn get_pw_status_bytes(&self) -> Vec<u8> {
        vec![
            if self.pin_data.pw1_valid_multiple { 0x01 } else { 0x00 },
            self.pin_data.pw1_max_length,
            self.pin_data.rc_max_length,
            self.pin_data.pw3_max_length,
            self.pin_data.pw1_retry_counter,
            self.pin_data.rc_retry_counter,
            self.pin_data.pw3_retry_counter,
        ]
    }

    /// Get all key fingerprints (C5) - 60 bytes total
    pub fn get_fingerprints(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(60);
        result.extend_from_slice(&self.key_sig.fingerprint_padded());
        result.extend_from_slice(&self.key_dec.fingerprint_padded());
        result.extend_from_slice(&self.key_aut.fingerprint_padded());
        result
    }

    /// Get all CA fingerprints (C6) - 60 bytes total
    pub fn get_ca_fingerprints(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(60);
        result.extend_from_slice(&self.key_sig.ca_fingerprint_padded());
        result.extend_from_slice(&self.key_dec.ca_fingerprint_padded());
        result.extend_from_slice(&self.key_aut.ca_fingerprint_padded());
        result
    }

    /// Get key generation timestamps (CD) - 12 bytes total
    pub fn get_key_timestamps(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(12);
        for ts in [self.key_sig.generation_time, self.key_dec.generation_time, self.key_aut.generation_time] {
            result.push((ts >> 24) as u8);
            result.push((ts >> 16) as u8);
            result.push((ts >> 8) as u8);
            result.push(ts as u8);
        }
        result
    }

    /// Get digital signature counter (93) - 3 bytes
    pub fn get_signature_counter_bytes(&self) -> Vec<u8> {
        vec![
            (self.signature_counter >> 16) as u8,
            (self.signature_counter >> 8) as u8,
            self.signature_counter as u8,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_attributes_rsa() {
        let attrs = AlgorithmAttributes::rsa(4096);
        let bytes = attrs.to_bytes();
        assert_eq!(bytes[0], AlgorithmID::RSA);
        assert_eq!(((bytes[1] as u16) << 8) | (bytes[2] as u16), 4096);
    }

    #[test]
    fn test_algorithm_attributes_ed25519() {
        let attrs = AlgorithmAttributes::ed25519();
        let bytes = attrs.to_bytes();
        assert_eq!(bytes[0], AlgorithmID::EDDSA);
        assert_eq!(&bytes[1..], CurveOID::ED25519);
    }

    #[test]
    fn test_card_state_serialization() {
        let state = CardState::default();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: CardState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version_major, state.version_major);
    }

    #[test]
    fn test_key_slot_has_key() {
        let slot = KeySlot::default();
        assert!(!slot.has_key());

        let mut slot_with_key = KeySlot::default();
        slot_with_key.fingerprint = vec![0x01; 20];
        assert!(slot_with_key.has_key());
    }

    #[test]
    fn test_get_aid() {
        let state = CardState::default();
        let aid = state.get_aid();
        assert_eq!(&aid[0..6], &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        assert_eq!(aid[6], 3);  // version major
        assert_eq!(aid[7], 4);  // version minor
    }

    #[test]
    fn test_base64_serialization() {
        let mut slot = KeySlot::default();
        slot.fingerprint = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let json = serde_json::to_string(&slot).unwrap();
        assert!(json.contains("3q2+7w==")); // base64 of DEADBEEF
    }
}
