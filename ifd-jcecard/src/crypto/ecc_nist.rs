//! NIST ECC Operations (P-256, P-384, P-521)
//!
//! ECDSA signing and ECDH using p256, p384, and p521 crates.

use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Signature};
use p384::ecdsa::{SigningKey as P384SigningKey, Signature as P384Signature};
use p521::ecdsa::{SigningKey as P521SigningKey, Signature as P521Signature};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use log::debug;

/// ECC curve types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    P256,
    P384,
    P521,
}

/// ECC operation errors
#[derive(Debug)]
pub enum EccError {
    KeyGenerationFailed(String),
    SigningFailed(String),
    ECDHFailed(String),
    InvalidKey(String),
    UnsupportedCurve,
}

/// NIST ECC Operations
pub struct EccNistOperations;

impl EccNistOperations {
    /// Generate a new ECC key pair
    /// Returns (private_key_bytes, public_key_bytes)
    pub fn generate_keypair(curve: EccCurve) -> Result<(Vec<u8>, Vec<u8>), EccError> {
        debug!("Generating {:?} keypair", curve);

        match curve {
            EccCurve::P256 => {
                let signing_key = P256SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                // Private key is 32 bytes
                let private_data = signing_key.to_bytes().to_vec();

                // Public key in uncompressed point format (0x04 || x || y)
                let point = verifying_key.to_encoded_point(false);
                let public_data = point.as_bytes().to_vec();

                Ok((private_data, public_data))
            }
            EccCurve::P384 => {
                let signing_key = P384SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                // Private key is 48 bytes
                let private_data = signing_key.to_bytes().to_vec();

                // Public key in uncompressed point format
                let point = verifying_key.to_encoded_point(false);
                let public_data = point.as_bytes().to_vec();

                Ok((private_data, public_data))
            }
            EccCurve::P521 => {
                let secret_key = p521::SecretKey::random(&mut OsRng);

                // Private key is 66 bytes
                let private_data = secret_key.to_bytes().to_vec();

                // Public key in uncompressed point format (0x04 || x || y)
                let point = secret_key.public_key().to_encoded_point(false);
                let public_data = point.as_bytes().to_vec();

                Ok((private_data, public_data))
            }
        }
    }

    /// Sign data with ECDSA
    pub fn sign(curve: EccCurve, private_key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, EccError> {
        match curve {
            EccCurve::P256 => {
                if private_key_bytes.len() != 32 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-256 key length: expected 32, got {}", private_key_bytes.len())
                    ));
                }

                let key_bytes: &[u8; 32] = private_key_bytes.try_into()
                    .map_err(|_| EccError::InvalidKey("Invalid key length".to_string()))?;

                let signing_key = P256SigningKey::from_bytes(key_bytes.into())
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                // Use sign_prehash since GPG sends the hash directly, not the original message
                let signature: P256Signature = signing_key.sign_prehash(data)
                    .map_err(|e| EccError::SigningFailed(e.to_string()))?;
                Ok(signature.to_bytes().to_vec())
            }
            EccCurve::P384 => {
                if private_key_bytes.len() != 48 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-384 key length: expected 48, got {}", private_key_bytes.len())
                    ));
                }

                let key_bytes: &[u8; 48] = private_key_bytes.try_into()
                    .map_err(|_| EccError::InvalidKey("Invalid key length".to_string()))?;

                let signing_key = P384SigningKey::from_bytes(key_bytes.into())
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                // Use sign_prehash since GPG sends the hash directly, not the original message
                let signature: P384Signature = signing_key.sign_prehash(data)
                    .map_err(|e| EccError::SigningFailed(e.to_string()))?;
                Ok(signature.to_bytes().to_vec())
            }
            EccCurve::P521 => {
                if private_key_bytes.len() != 66 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-521 key length: expected 66, got {}", private_key_bytes.len())
                    ));
                }

                let signing_key = P521SigningKey::from_slice(private_key_bytes)
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                // Use sign_prehash since GPG sends the hash directly, not the original message
                let signature: P521Signature = signing_key.sign_prehash(data)
                    .map_err(|e| EccError::SigningFailed(e.to_string()))?;
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    /// Get the public key from a private key
    pub fn get_public_key(curve: EccCurve, private_key_bytes: &[u8]) -> Result<Vec<u8>, EccError> {
        match curve {
            EccCurve::P256 => {
                if private_key_bytes.len() != 32 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-256 key length: expected 32, got {}", private_key_bytes.len())
                    ));
                }

                let key_bytes: &[u8; 32] = private_key_bytes.try_into()
                    .map_err(|_| EccError::InvalidKey("Invalid key length".to_string()))?;

                let signing_key = P256SigningKey::from_bytes(key_bytes.into())
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                let point = signing_key.verifying_key().to_encoded_point(false);
                Ok(point.as_bytes().to_vec())
            }
            EccCurve::P384 => {
                if private_key_bytes.len() != 48 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-384 key length: expected 48, got {}", private_key_bytes.len())
                    ));
                }

                let key_bytes: &[u8; 48] = private_key_bytes.try_into()
                    .map_err(|_| EccError::InvalidKey("Invalid key length".to_string()))?;

                let signing_key = P384SigningKey::from_bytes(key_bytes.into())
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                let point = signing_key.verifying_key().to_encoded_point(false);
                Ok(point.as_bytes().to_vec())
            }
            EccCurve::P521 => {
                if private_key_bytes.len() != 66 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-521 key length: expected 66, got {}", private_key_bytes.len())
                    ));
                }

                let secret_key = p521::SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| EccError::InvalidKey(e.to_string()))?;

                let point = secret_key.public_key().to_encoded_point(false);
                Ok(point.as_bytes().to_vec())
            }
        }
    }

    /// Get expected private key size for curve
    pub fn private_key_size(curve: EccCurve) -> usize {
        match curve {
            EccCurve::P256 => 32,
            EccCurve::P384 => 48,
            EccCurve::P521 => 66,
        }
    }

    /// Get expected public key size for curve (uncompressed)
    pub fn public_key_size(curve: EccCurve) -> usize {
        match curve {
            EccCurve::P256 => 65,  // 1 + 32 + 32
            EccCurve::P384 => 97,  // 1 + 48 + 48
            EccCurve::P521 => 133, // 1 + 66 + 66
        }
    }

    /// Perform ECDH key agreement
    /// Returns shared secret
    pub fn ecdh(curve: EccCurve, private_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<Vec<u8>, EccError> {
        debug!("ECDH {:?}: private {} bytes, public {} bytes",
               curve, private_key_bytes.len(), public_key_bytes.len());

        match curve {
            EccCurve::P256 => {
                use p256::{SecretKey, PublicKey};
                use p256::ecdh::diffie_hellman;

                if private_key_bytes.len() != 32 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-256 private key length: expected 32, got {}",
                                private_key_bytes.len())
                    ));
                }

                let secret_key = SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-256 private key: {}", e)))?;

                let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-256 public key: {}", e)))?;

                let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
                Ok(shared_secret.raw_secret_bytes().to_vec())
            }
            EccCurve::P384 => {
                use p384::{SecretKey, PublicKey};
                use p384::ecdh::diffie_hellman;

                if private_key_bytes.len() != 48 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-384 private key length: expected 48, got {}",
                                private_key_bytes.len())
                    ));
                }

                let secret_key = SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-384 private key: {}", e)))?;

                let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-384 public key: {}", e)))?;

                let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
                Ok(shared_secret.raw_secret_bytes().to_vec())
            }
            EccCurve::P521 => {
                use p521::{SecretKey, PublicKey};
                use p521::ecdh::diffie_hellman;

                if private_key_bytes.len() != 66 {
                    return Err(EccError::InvalidKey(
                        format!("Invalid P-521 private key length: expected 66, got {}",
                                private_key_bytes.len())
                    ));
                }

                let secret_key = SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-521 private key: {}", e)))?;

                let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EccError::InvalidKey(format!("Invalid P-521 public key: {}", e)))?;

                let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
                Ok(shared_secret.raw_secret_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_p256_keypair() {
        let (private, public) = EccNistOperations::generate_keypair(EccCurve::P256).unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04); // Uncompressed point
    }

    #[test]
    fn test_generate_p384_keypair() {
        let (private, public) = EccNistOperations::generate_keypair(EccCurve::P384).unwrap();
        assert_eq!(private.len(), 48);
        assert_eq!(public.len(), 97);
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn test_p256_sign() {
        use sha2::{Sha256, Digest};
        let (private, _) = EccNistOperations::generate_keypair(EccCurve::P256).unwrap();
        // sign_prehash expects a hash, not raw data
        let hash = Sha256::digest(b"test message");
        let signature = EccNistOperations::sign(EccCurve::P256, &private, &hash).unwrap();
        assert_eq!(signature.len(), 64); // r || s, each 32 bytes
    }

    #[test]
    fn test_get_public_key() {
        let (private, public) = EccNistOperations::generate_keypair(EccCurve::P256).unwrap();
        let derived_public = EccNistOperations::get_public_key(EccCurve::P256, &private).unwrap();
        assert_eq!(public, derived_public);
    }

    #[test]
    fn test_p256_ecdh() {
        let (private_a, public_a) = EccNistOperations::generate_keypair(EccCurve::P256).unwrap();
        let (private_b, public_b) = EccNistOperations::generate_keypair(EccCurve::P256).unwrap();

        let shared_a = EccNistOperations::ecdh(EccCurve::P256, &private_a, &public_b).unwrap();
        let shared_b = EccNistOperations::ecdh(EccCurve::P256, &private_b, &public_a).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    #[test]
    fn test_p384_ecdh() {
        let (private_a, public_a) = EccNistOperations::generate_keypair(EccCurve::P384).unwrap();
        let (private_b, public_b) = EccNistOperations::generate_keypair(EccCurve::P384).unwrap();

        let shared_a = EccNistOperations::ecdh(EccCurve::P384, &private_a, &public_b).unwrap();
        let shared_b = EccNistOperations::ecdh(EccCurve::P384, &private_b, &public_a).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 48);
    }

    #[test]
    fn test_generate_p521_keypair() {
        let (private, public) = EccNistOperations::generate_keypair(EccCurve::P521).unwrap();
        assert_eq!(private.len(), 66);
        assert_eq!(public.len(), 133);
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn test_p521_sign() {
        use sha2::{Sha512, Digest};
        let (private, _) = EccNistOperations::generate_keypair(EccCurve::P521).unwrap();
        let hash = Sha512::digest(b"test message");
        let signature = EccNistOperations::sign(EccCurve::P521, &private, &hash).unwrap();
        assert_eq!(signature.len(), 132); // r || s, each 66 bytes
    }

    #[test]
    fn test_p521_get_public_key() {
        let (private, public) = EccNistOperations::generate_keypair(EccCurve::P521).unwrap();
        let derived_public = EccNistOperations::get_public_key(EccCurve::P521, &private).unwrap();
        assert_eq!(public, derived_public);
    }

    #[test]
    fn test_p521_ecdh() {
        let (private_a, public_a) = EccNistOperations::generate_keypair(EccCurve::P521).unwrap();
        let (private_b, public_b) = EccNistOperations::generate_keypair(EccCurve::P521).unwrap();

        let shared_a = EccNistOperations::ecdh(EccCurve::P521, &private_a, &public_b).unwrap();
        let shared_b = EccNistOperations::ecdh(EccCurve::P521, &private_b, &public_a).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 66);
    }
}
