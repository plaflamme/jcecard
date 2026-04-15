//! OpenPGP Key Fingerprint Calculation
//!
//! Calculates OpenPGP v4 fingerprints using SHA-1.

use sha1::{Sha1, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Calculate OpenPGP v4 fingerprint for an RSA key
///
/// Format: SHA-1(0x99 || 2-byte packet length || packet body)
/// Packet body: version(1) || timestamp(4) || algorithm(1) || MPI(s)
pub fn calculate_fingerprint_rsa(
    n: &[u8],  // Modulus
    e: &[u8],  // Exponent
    timestamp: u32,
) -> Vec<u8> {
    // MPI format: 2-byte bit count || value
    let n_bits = (n.len() * 8) as u16;
    let e_bits = (e.len() * 8) as u16;

    // Packet body
    let mut packet = Vec::new();
    packet.push(4);  // Version 4
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(1);  // Algorithm: RSA

    // MPI for n
    packet.extend_from_slice(&n_bits.to_be_bytes());
    packet.extend_from_slice(n);

    // MPI for e
    packet.extend_from_slice(&e_bits.to_be_bytes());
    packet.extend_from_slice(e);

    // Hash with prefix
    let packet_len = packet.len() as u16;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(packet_len.to_be_bytes());
    hasher.update(&packet);

    hasher.finalize().to_vec()
}

/// Calculate OpenPGP v4 fingerprint for an EdDSA (Ed25519) key
pub fn calculate_fingerprint_eddsa(
    public_key: &[u8],  // 32 bytes for Ed25519
    timestamp: u32,
) -> Vec<u8> {
    // OID for Ed25519
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

    // Packet body
    let mut packet = Vec::new();
    packet.push(4);  // Version 4
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(22);  // Algorithm: EdDSA

    // OID length + OID
    packet.push(oid.len() as u8);
    packet.extend_from_slice(&oid);

    // MPI for public key (with 0x40 prefix for native format)
    let pk_with_prefix = [&[0x40], public_key].concat();
    let pk_bits = (pk_with_prefix.len() * 8) as u16;
    packet.extend_from_slice(&pk_bits.to_be_bytes());
    packet.extend_from_slice(&pk_with_prefix);

    // Hash with prefix
    let packet_len = packet.len() as u16;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(packet_len.to_be_bytes());
    hasher.update(&packet);

    hasher.finalize().to_vec()
}

/// Calculate OpenPGP v4 fingerprint for an ECDH (X25519) key
pub fn calculate_fingerprint_ecdh_x25519(
    public_key: &[u8],  // 32 bytes for X25519
    timestamp: u32,
) -> Vec<u8> {
    // OID for X25519
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

    // Packet body
    let mut packet = Vec::new();
    packet.push(4);  // Version 4
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(18);  // Algorithm: ECDH

    // OID length + OID
    packet.push(oid.len() as u8);
    packet.extend_from_slice(&oid);

    // MPI for public key (with 0x40 prefix for native format)
    let pk_with_prefix = [&[0x40], public_key].concat();
    let pk_bits = (pk_with_prefix.len() * 8) as u16;
    packet.extend_from_slice(&pk_bits.to_be_bytes());
    packet.extend_from_slice(&pk_with_prefix);

    // KDF parameters: hash algo (SHA256=8), cipher algo (AES128=7)
    packet.push(3);  // KDF params length
    packet.push(1);  // Reserved
    packet.push(8);  // SHA256
    packet.push(7);  // AES128

    // Hash with prefix
    let packet_len = packet.len() as u16;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(packet_len.to_be_bytes());
    hasher.update(&packet);

    hasher.finalize().to_vec()
}

/// Calculate OpenPGP v4 fingerprint for an ECDSA key (P-256, P-384, secp256k1)
pub fn calculate_fingerprint_ecdsa(
    public_key: &[u8],  // Uncompressed point (65 bytes for P-256, 97 for P-384)
    curve_oid: &[u8],
    timestamp: u32,
) -> Vec<u8> {
    // Packet body
    let mut packet = Vec::new();
    packet.push(4);  // Version 4
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(19);  // Algorithm: ECDSA

    // OID length + OID
    packet.push(curve_oid.len() as u8);
    packet.extend_from_slice(curve_oid);

    // MPI for public key
    let pk_bits = (public_key.len() * 8) as u16;
    packet.extend_from_slice(&pk_bits.to_be_bytes());
    packet.extend_from_slice(public_key);

    // Hash with prefix
    let packet_len = packet.len() as u16;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(packet_len.to_be_bytes());
    hasher.update(&packet);

    hasher.finalize().to_vec()
}

/// Calculate OpenPGP v4 fingerprint for an ECDH key with NIST curves (P-256, P-384, secp256k1)
pub fn calculate_fingerprint_ecdh(
    public_key: &[u8],  // Uncompressed point (65 bytes for P-256, 97 for P-384)
    curve_oid: &[u8],
    timestamp: u32,
) -> Vec<u8> {
    // Packet body
    let mut packet = Vec::new();
    packet.push(4);  // Version 4
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.push(18);  // Algorithm: ECDH

    // OID length + OID
    packet.push(curve_oid.len() as u8);
    packet.extend_from_slice(curve_oid);

    // MPI for public key
    let pk_bits = (public_key.len() * 8) as u16;
    packet.extend_from_slice(&pk_bits.to_be_bytes());
    packet.extend_from_slice(public_key);

    // KDF parameters: hash algo, cipher algo
    // P-256/secp256k1: SHA256(8)/AES128(7), P-384: SHA384(9)/AES256(9), P-521: SHA512(10)/AES256(9)
    let (hash_algo, cipher_algo) = if public_key.len() == 133 {
        (10, 9)  // SHA512, AES256 for P-521
    } else if public_key.len() == 97 {
        (9, 9)  // SHA384, AES256 for P-384
    } else {
        (8, 7)  // SHA256, AES128 for P-256/secp256k1
    };
    packet.push(3);  // KDF params length
    packet.push(1);  // Reserved
    packet.push(hash_algo);
    packet.push(cipher_algo);

    // Hash with prefix
    let packet_len = packet.len() as u16;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(packet_len.to_be_bytes());
    hasher.update(&packet);

    hasher.finalize().to_vec()
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_length() {
        let n = vec![0u8; 256];  // 2048-bit modulus
        let e = vec![0x01, 0x00, 0x01];  // 65537
        let fp = calculate_fingerprint_rsa(&n, &e, 0);
        assert_eq!(fp.len(), 20);  // SHA-1 output
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let n = vec![0u8; 256];
        let e = vec![0x01, 0x00, 0x01];
        let timestamp = 1234567890u32;

        let fp1 = calculate_fingerprint_rsa(&n, &e, timestamp);
        let fp2 = calculate_fingerprint_rsa(&n, &e, timestamp);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_ed25519_length() {
        let public_key = vec![0u8; 32];
        let fp = calculate_fingerprint_eddsa(&public_key, 0);
        assert_eq!(fp.len(), 20);
    }

    #[test]
    fn test_fingerprint_x25519_length() {
        let public_key = vec![0u8; 32];
        let fp = calculate_fingerprint_ecdh_x25519(&public_key, 0);
        assert_eq!(fp.len(), 20);
    }
}
