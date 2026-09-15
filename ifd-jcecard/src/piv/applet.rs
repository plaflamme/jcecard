//! PIV Applet implementation
//!
//! Main dispatcher for PIV card commands following NIST SP 800-73-4.

use crate::apdu::{APDU, Response, SW};
use crate::tlv::{TLVBuilder, TLVEncoder};
use crate::crypto::rsa::RsaOperations;
use crate::crypto::ecc_nist::{EccNistOperations, EccCurve};
use crate::crypto::tdes::TDesOperations;
use super::data_objects::{PIVDataObjects, PIVKeySlot, PIVAlgorithm, PIVKeyData};
use super::security_state::PIVSecurityState;
use log::{debug, info, warn};

/// PIV Application Identifier
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// PIV Key Reference bytes
pub mod key_ref {
    pub const PIV_PIN: u8 = 0x80;
    pub const PIV_PUK: u8 = 0x81;
    pub const MGMT_KEY: u8 = 0x9B;
}

/// PIV Card Applet
pub struct PIVApplet {
    data_objects: PIVDataObjects,
    security_state: PIVSecurityState,
    response_buffer: Vec<u8>,
    response_offset: usize,
    current_challenge: Option<Vec<u8>>,
    version: (u8, u8, u8),
    serial: u32,
    /// Buffer for command chaining (PUT DATA with large certificates)
    command_chain_buffer: Vec<u8>,
    /// INS of the command being chained
    command_chain_ins: Option<u8>,
    /// P1 of the command being chained
    command_chain_p1: u8,
    /// P2 of the command being chained
    command_chain_p2: u8,
}

impl PIVApplet {
    /// Create a new PIV applet
    pub fn new() -> Self {
        // Generate random serial
        let mut serial_bytes = [0u8; 4];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut serial_bytes);
        let serial = u32::from_be_bytes(serial_bytes);

        Self {
            data_objects: PIVDataObjects::new(),
            security_state: PIVSecurityState::new(),
            response_buffer: Vec::new(),
            response_offset: 0,
            current_challenge: None,
            version: (5, 4, 3),
            serial,
            command_chain_buffer: Vec::new(),
            command_chain_ins: None,
            command_chain_p1: 0,
            command_chain_p2: 0,
        }
    }

    /// Process an APDU command and return the response
    pub fn process_apdu(&mut self, cmd: &APDU) -> Response {
        debug!("PIV APDU: CLA={:02X} INS={:02X} P1={:02X} P2={:02X} data_len={}",
               cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data.len());

        // Check for command chaining (CLA bit 4 set means more data follows)
        let is_chaining = (cmd.cla & 0x10) != 0;

        // Handle command chaining for PUT DATA (large certificates)
        if is_chaining || self.command_chain_ins.is_some() {
            // If this is a new chain, store the command parameters
            if self.command_chain_ins.is_none() {
                self.command_chain_ins = Some(cmd.ins);
                self.command_chain_p1 = cmd.p1;
                self.command_chain_p2 = cmd.p2;
                self.command_chain_buffer.clear();
            }

            // Verify same instruction for chained commands
            if self.command_chain_ins != Some(cmd.ins) {
                self.command_chain_ins = None;
                self.command_chain_buffer.clear();
                return Response::error(SW::CONDITIONS_NOT_SATISFIED);
            }

            // Append data to buffer
            self.command_chain_buffer.extend_from_slice(&cmd.data);
            debug!("Command chaining: buffered {} bytes, total {}",
                   cmd.data.len(), self.command_chain_buffer.len());

            if is_chaining {
                // More data expected, return success
                return Response::ok();
            } else {
                // Last in chain - process the complete data
                let complete_cmd = APDU {
                    cla: cmd.cla & 0xEF, // Clear chaining bit
                    ins: self.command_chain_ins.unwrap(),
                    p1: self.command_chain_p1,
                    p2: self.command_chain_p2,
                    data: std::mem::take(&mut self.command_chain_buffer),
                    le: cmd.le,
                };
                self.command_chain_ins = None;

                debug!("Command chain complete: {} bytes total", complete_cmd.data.len());

                // Process the complete command
                return match complete_cmd.ins {
                    0xDB => self.handle_put_data(&complete_cmd),
                    _ => {
                        warn!("Command chaining not supported for INS {:02X}", complete_cmd.ins);
                        Response::error(SW::INS_NOT_SUPPORTED)
                    }
                };
            }
        }

        match cmd.ins {
            0xA4 => self.handle_select(cmd),
            0x20 => self.handle_verify(cmd),
            0x24 => self.handle_change_reference_data(cmd),
            0x2C => self.handle_reset_retry_counter(cmd),
            0xCB => self.handle_get_data(cmd),
            0xDB => self.handle_put_data(cmd),
            0x47 => self.handle_generate_key(cmd),
            0x87 => self.handle_general_authenticate(cmd),
            0xC0 => self.handle_get_response(cmd),
            0xFD => self.handle_get_version(cmd),
            0xF8 => self.handle_get_serial(cmd),
            _ => {
                warn!("Unknown PIV instruction: {:02X}", cmd.ins);
                Response::error(SW::INS_NOT_SUPPORTED)
            }
        }
    }

    /// Get a reference to the data objects
    pub fn get_data_objects(&self) -> &PIVDataObjects {
        &self.data_objects
    }

    /// Get a mutable reference to the data objects
    pub fn get_data_objects_mut(&mut self) -> &mut PIVDataObjects {
        &mut self.data_objects
    }

    /// Reset security state (on card reset)
    pub fn reset(&mut self) {
        self.security_state.clear_all();
        self.response_buffer.clear();
        self.response_offset = 0;
        self.current_challenge = None;
    }

    // =========================================================================
    // Command Handlers
    // =========================================================================

    /// Handle SELECT command (INS A4)
    fn handle_select(&mut self, cmd: &APDU) -> Response {
        if cmd.p1 != 0x04 {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Check AID
        if !cmd.data.starts_with(PIV_AID) {
            return Response::error(SW::FILE_NOT_FOUND);
        }

        self.security_state.clear_all();
        self.current_challenge = None;

        // Build response: Application Property Template
        let response_data = [
            0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,  // Application identifier (PIV version 1.0)
            0x79, 0x07,  // Coexistent tag allocation authority
            0x4F, 0x05,  // AID tag
        ].iter().chain(PIV_AID.iter()).copied().collect::<Vec<u8>>();

        info!("PIV application selected");
        Response::success(response_data)
    }

    /// Handle VERIFY command (INS 20)
    fn handle_verify(&mut self, cmd: &APDU) -> Response {
        match cmd.p2 {
            key_ref::PIV_PIN => {
                if cmd.data.is_empty() {
                    // Return retry counter
                    return Response::counter_warning(self.data_objects.pin_retries);
                }

                // Strip FF padding
                let pin: Vec<u8> = cmd.data.iter()
                    .take_while(|&&b| b != 0xFF)
                    .copied()
                    .collect();

                if self.data_objects.pin_retries == 0 {
                    return Response::error(SW::AUTH_METHOD_BLOCKED);
                }

                if pin == self.data_objects.pin {
                    self.security_state.set_pin_verified(true);
                    self.data_objects.pin_retries = 3; // Reset counter
                    info!("PIV PIN verified successfully");
                    Response::ok()
                } else {
                    self.data_objects.pin_retries = self.data_objects.pin_retries.saturating_sub(1);
                    warn!("PIV PIN verification failed, {} retries remaining", self.data_objects.pin_retries);
                    if self.data_objects.pin_retries == 0 {
                        Response::error(SW::AUTH_METHOD_BLOCKED)
                    } else {
                        Response::counter_warning(self.data_objects.pin_retries)
                    }
                }
            }
            key_ref::PIV_PUK => {
                if cmd.data.is_empty() {
                    return Response::counter_warning(self.data_objects.puk_retries);
                }

                if self.data_objects.puk_retries == 0 {
                    return Response::error(SW::AUTH_METHOD_BLOCKED);
                }

                if cmd.data == self.data_objects.puk {
                    self.data_objects.puk_retries = 3;
                    Response::ok()
                } else {
                    self.data_objects.puk_retries = self.data_objects.puk_retries.saturating_sub(1);
                    if self.data_objects.puk_retries == 0 {
                        Response::error(SW::AUTH_METHOD_BLOCKED)
                    } else {
                        Response::counter_warning(self.data_objects.puk_retries)
                    }
                }
            }
            _ => Response::error(SW::WRONG_P1_P2),
        }
    }

    /// Handle CHANGE REFERENCE DATA command (INS 24)
    fn handle_change_reference_data(&mut self, cmd: &APDU) -> Response {
        if cmd.data.len() != 16 {
            return Response::error(SW::WRONG_LENGTH);
        }

        let old_value: Vec<u8> = cmd.data[..8].iter()
            .take_while(|&&b| b != 0xFF)
            .copied()
            .collect();
        let new_value: Vec<u8> = cmd.data[8..].iter()
            .take_while(|&&b| b != 0xFF)
            .copied()
            .collect();

        match cmd.p2 {
            key_ref::PIV_PIN => {
                if self.data_objects.pin_retries == 0 {
                    return Response::error(SW::AUTH_METHOD_BLOCKED);
                }

                if old_value == self.data_objects.pin {
                    self.data_objects.pin = new_value;
                    self.data_objects.pin_retries = 3;
                    info!("PIV PIN changed successfully");
                    Response::ok()
                } else {
                    self.data_objects.pin_retries = self.data_objects.pin_retries.saturating_sub(1);
                    if self.data_objects.pin_retries == 0 {
                        Response::error(SW::AUTH_METHOD_BLOCKED)
                    } else {
                        Response::counter_warning(self.data_objects.pin_retries)
                    }
                }
            }
            key_ref::PIV_PUK => {
                if self.data_objects.puk_retries == 0 {
                    return Response::error(SW::AUTH_METHOD_BLOCKED);
                }

                if old_value == self.data_objects.puk {
                    self.data_objects.puk = new_value;
                    self.data_objects.puk_retries = 3;
                    info!("PIV PUK changed successfully");
                    Response::ok()
                } else {
                    self.data_objects.puk_retries = self.data_objects.puk_retries.saturating_sub(1);
                    if self.data_objects.puk_retries == 0 {
                        Response::error(SW::AUTH_METHOD_BLOCKED)
                    } else {
                        Response::counter_warning(self.data_objects.puk_retries)
                    }
                }
            }
            _ => Response::error(SW::WRONG_P1_P2),
        }
    }

    /// Handle RESET RETRY COUNTER command (INS 2C)
    fn handle_reset_retry_counter(&mut self, cmd: &APDU) -> Response {
        if cmd.p2 != key_ref::PIV_PIN {
            return Response::error(SW::WRONG_P1_P2);
        }

        if cmd.data.len() != 16 {
            return Response::error(SW::WRONG_LENGTH);
        }

        let puk = &cmd.data[..8];
        let new_pin: Vec<u8> = cmd.data[8..].iter()
            .take_while(|&&b| b != 0xFF)
            .copied()
            .collect();

        if self.data_objects.puk_retries == 0 {
            return Response::error(SW::AUTH_METHOD_BLOCKED);
        }

        if puk == self.data_objects.puk.as_slice() {
            self.data_objects.pin = new_pin;
            self.data_objects.pin_retries = 3;
            self.data_objects.puk_retries = 3;
            info!("PIV PIN reset with PUK successfully");
            Response::ok()
        } else {
            self.data_objects.puk_retries = self.data_objects.puk_retries.saturating_sub(1);
            if self.data_objects.puk_retries == 0 {
                Response::error(SW::AUTH_METHOD_BLOCKED)
            } else {
                Response::counter_warning(self.data_objects.puk_retries)
            }
        }
    }

    /// Handle GET DATA command (INS CB)
    fn handle_get_data(&self, cmd: &APDU) -> Response {
        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Parse TLV to get object ID (5C tag)
        if cmd.data.len() < 2 || cmd.data[0] != 0x5C {
            return Response::error(SW::WRONG_DATA);
        }

        let tag_len = cmd.data[1] as usize;
        if cmd.data.len() < 2 + tag_len {
            return Response::error(SW::WRONG_DATA);
        }

        let object_id = &cmd.data[2..2 + tag_len];

        // Get the data object
        let data = match object_id {
            // Card Holder Unique Identifier (CHUID) - 5FC102
            [0x5F, 0xC1, 0x02] => {
                if self.data_objects.chuid.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.chuid
            }
            // Cardholder Capability Container (CCC) - 5FC107
            [0x5F, 0xC1, 0x07] => {
                if self.data_objects.ccc.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.ccc
            }
            // X.509 Certificate for PIV Authentication - 5FC105
            [0x5F, 0xC1, 0x05] => {
                if self.data_objects.key_9a.certificate.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.key_9a.certificate
            }
            // X.509 Certificate for Digital Signature - 5FC10A
            [0x5F, 0xC1, 0x0A] => {
                if self.data_objects.key_9c.certificate.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.key_9c.certificate
            }
            // X.509 Certificate for Key Management - 5FC10B
            [0x5F, 0xC1, 0x0B] => {
                if self.data_objects.key_9d.certificate.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.key_9d.certificate
            }
            // X.509 Certificate for Card Authentication - 5FC101
            [0x5F, 0xC1, 0x01] => {
                if self.data_objects.key_9e.certificate.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.key_9e.certificate
            }
            // Discovery Object - 7E
            [0x7E] => {
                if self.data_objects.discovery.is_empty() {
                    return Response::error(SW::FILE_NOT_FOUND);
                }
                &self.data_objects.discovery
            }
            _ => {
                debug!("Unknown PIV data object: {:02X?}", object_id);
                return Response::error(SW::FILE_NOT_FOUND);
            }
        };

        // Wrap in 53 tag
        let response = TLVEncoder::encode(0x53, data);
        debug!("GET DATA for object {:02X?}: {} bytes", object_id, response.len());
        Response::success(response)
    }

    /// Handle PUT DATA command (INS DB)
    fn handle_put_data(&mut self, cmd: &APDU) -> Response {
        if !self.security_state.is_management_key_authenticated() {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Parse TLV to get object ID (5C tag)
        if cmd.data.len() < 2 || cmd.data[0] != 0x5C {
            return Response::error(SW::WRONG_DATA);
        }

        let tag_len = cmd.data[1] as usize;
        if cmd.data.len() < 2 + tag_len {
            return Response::error(SW::WRONG_DATA);
        }

        let object_id = &cmd.data[2..2 + tag_len];
        let remaining = &cmd.data[2 + tag_len..];

        // Find the data (53 tag)
        if remaining.is_empty() || remaining[0] != 0x53 {
            return Response::error(SW::WRONG_DATA);
        }

        // Parse length
        let (data_len, data_offset) = if remaining.len() < 2 {
            return Response::error(SW::WRONG_DATA);
        } else if remaining[1] == 0x82 {
            if remaining.len() < 4 {
                return Response::error(SW::WRONG_DATA);
            }
            let len = ((remaining[2] as usize) << 8) | (remaining[3] as usize);
            (len, 4)
        } else if remaining[1] == 0x81 {
            if remaining.len() < 3 {
                return Response::error(SW::WRONG_DATA);
            }
            (remaining[2] as usize, 3)
        } else {
            (remaining[1] as usize, 2)
        };

        if remaining.len() < data_offset + data_len {
            return Response::error(SW::WRONG_DATA);
        }

        let data = remaining[data_offset..data_offset + data_len].to_vec();

        // Store the data
        match object_id {
            [0x5F, 0xC1, 0x02] => self.data_objects.chuid = data,
            [0x5F, 0xC1, 0x07] => self.data_objects.ccc = data,
            [0x5F, 0xC1, 0x05] => self.data_objects.key_9a.certificate = data,
            [0x5F, 0xC1, 0x0A] => self.data_objects.key_9c.certificate = data,
            [0x5F, 0xC1, 0x0B] => self.data_objects.key_9d.certificate = data,
            [0x5F, 0xC1, 0x01] => self.data_objects.key_9e.certificate = data,
            [0x7E] => self.data_objects.discovery = data,
            _ => {
                debug!("Unknown PIV data object for PUT: {:02X?}", object_id);
                return Response::error(SW::FILE_NOT_FOUND);
            }
        }

        info!("PUT DATA for object {:02X?}: {} bytes", object_id, data_len);
        Response::ok()
    }

    /// Handle GENERATE ASYMMETRIC KEY PAIR command (INS 47)
    fn handle_generate_key(&mut self, cmd: &APDU) -> Response {
        if !self.security_state.is_management_key_authenticated() {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        // Get slot from P2
        let slot = match PIVKeySlot::from_byte(cmd.p2) {
            Some(s) => s,
            None => return Response::error(SW::WRONG_P1_P2),
        };

        // Parse algorithm from data (AC 03 80 01 XX)
        if cmd.data.len() < 5 || cmd.data[0] != 0xAC {
            return Response::error(SW::WRONG_DATA);
        }

        // Find 80 tag for algorithm
        let mut idx = 2;
        let mut algorithm_byte = None;
        while idx + 2 <= cmd.data.len() {
            let tag = cmd.data[idx];
            let length = cmd.data[idx + 1] as usize;
            if tag == 0x80 && length == 1 && idx + 2 < cmd.data.len() {
                algorithm_byte = Some(cmd.data[idx + 2]);
                break;
            }
            idx += 2 + length;
        }

        let algorithm = match algorithm_byte.and_then(PIVAlgorithm::from_byte) {
            Some(a) => a,
            None => return Response::error(SW::WRONG_DATA),
        };

        info!("Generating {:?} key in slot {:?}", algorithm, slot);

        match algorithm {
            PIVAlgorithm::RSA2048 => self.generate_rsa_key(slot, 2048),
            PIVAlgorithm::ECCP256 => self.generate_ecc_key(slot, algorithm),
            PIVAlgorithm::ECCP384 => self.generate_ecc_key(slot, algorithm),
            PIVAlgorithm::TDES => Response::error(SW::FUNCTION_NOT_SUPPORTED),
        }
    }

    /// Generate RSA key pair
    fn generate_rsa_key(&mut self, slot: PIVKeySlot, bits: usize) -> Response {
        match RsaOperations::generate_keypair(bits) {
            Ok((priv_key, pub_key_data)) => {
                let n = RsaOperations::get_modulus(&pub_key_data).unwrap_or_default();
                let e = RsaOperations::get_exponent(&pub_key_data).unwrap_or_default();

                // Build public key response (7F49 template)
                let pub_tlv = TLVBuilder::new()
                    .add(0x81, &n)
                    .add(0x82, &e)
                    .wrap(0x7F49)
                    .build();

                // Store key
                if let Some(key_data) = self.data_objects.get_key_mut(slot) {
                    key_data.algorithm = PIVAlgorithm::RSA2048 as u8;
                    key_data.private_key = priv_key;
                    key_data.public_key = pub_tlv.clone();
                }

                info!("Generated RSA-{} key in slot {:?}, modulus {} bytes", bits, slot, n.len());
                Response::success(pub_tlv)
            }
            Err(_) => Response::error(SW::EXEC_ERROR),
        }
    }

    /// Generate ECC key pair
    fn generate_ecc_key(&mut self, slot: PIVKeySlot, algorithm: PIVAlgorithm) -> Response {
        let curve = if algorithm == PIVAlgorithm::ECCP256 {
            EccCurve::P256
        } else {
            EccCurve::P384
        };

        match EccNistOperations::generate_keypair(curve) {
            Ok((priv_key, pub_point)) => {
                // Build public key response (7F49 template with 86 tag for EC point)
                let pub_tlv = TLVBuilder::new()
                    .add(0x86, &pub_point)
                    .wrap(0x7F49)
                    .build();

                // Store key
                if let Some(key_data) = self.data_objects.get_key_mut(slot) {
                    key_data.algorithm = algorithm as u8;
                    key_data.private_key = priv_key;
                    key_data.public_key = pub_tlv.clone();
                }

                info!("Generated ECC {:?} key in slot {:?}", algorithm, slot);
                Response::success(pub_tlv)
            }
            Err(_) => Response::error(SW::EXEC_ERROR),
        }
    }

    /// Handle GENERAL AUTHENTICATE command (INS 87)
    fn handle_general_authenticate(&mut self, cmd: &APDU) -> Response {
        let _algo = cmd.p1;
        let key_ref = cmd.p2;

        // Parse 7C template
        if cmd.data.is_empty() || cmd.data[0] != 0x7C {
            return Response::error(SW::WRONG_DATA);
        }

        // Parse contents
        let contents = if cmd.data.len() > 2 { &cmd.data[2..] } else { &[] };
        let mut tags: std::collections::HashMap<u8, Vec<u8>> = std::collections::HashMap::new();
        let mut idx = 0;
        while idx + 1 < contents.len() {
            let tag = contents[idx];
            let length = contents[idx + 1] as usize;
            let value = if idx + 2 + length <= contents.len() {
                contents[idx + 2..idx + 2 + length].to_vec()
            } else {
                Vec::new()
            };
            tags.insert(tag, value);
            idx += 2 + length;
        }

        // Management key authentication
        if key_ref == key_ref::MGMT_KEY {
            return self.authenticate_mgmt_key(&tags);
        }

        // Key operations (signing, decryption)
        let slot = match PIVKeySlot::from_byte(key_ref) {
            Some(s) => s,
            None => return Response::error(SW::WRONG_P1_P2),
        };

        // Check PIN for slots that require it (not card authentication)
        if slot != PIVKeySlot::CardAuthentication && !self.security_state.is_pin_verified() {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        // Get key for this slot
        let key_data = match self.data_objects.get_key(slot) {
            Some(k) if !k.private_key.is_empty() => k.clone(),
            _ => return Response::error(SW::REFERENCED_DATA_NOT_FOUND),
        };

        // Handle signing (82 tag with empty value = request signature)
        if let Some(empty_82) = tags.get(&0x82) {
            if empty_82.is_empty() {
                if let Some(challenge) = tags.get(&0x81) {
                    return self.sign_data(&key_data, challenge);
                }
                return Response::error(SW::WRONG_DATA);
            }
        }

        // Handle decryption/ECDH (85 tag for cipher text)
        if let Some(cipher_text) = tags.get(&0x85) {
            return self.decrypt_data(&key_data, cipher_text);
        }

        Response::error(SW::WRONG_DATA)
    }

    /// Authenticate management key using challenge-response
    fn authenticate_mgmt_key(&mut self, tags: &std::collections::HashMap<u8, Vec<u8>>) -> Response {
        // Step 1: Request challenge (empty 80 tag)
        if let Some(witness_tag) = tags.get(&0x80) {
            if witness_tag.is_empty() && !tags.contains_key(&0x81) {
                // Generate random witness (challenge)
                let mut witness = vec![0u8; 8];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut witness);
                self.current_challenge = Some(witness.clone());

                // Encrypt the witness with management key
                match TDesOperations::encrypt_ecb(&self.data_objects.management_key, &witness) {
                    Ok(encrypted_witness) => {
                        let mut response = vec![0x7C, 0x0A, 0x80, 0x08];
                        response.extend_from_slice(&encrypted_witness);
                        debug!("Management key auth: witness {:02X?}, encrypted {:02X?}", witness, encrypted_witness);
                        return Response::success(response);
                    }
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            }
        }

        // Step 2: Verify response and host challenge
        if let (Some(host_witness), Some(host_challenge)) = (tags.get(&0x80), tags.get(&0x81)) {
            let original_challenge = match &self.current_challenge {
                Some(c) => c.clone(),
                None => return Response::error(SW::CONDITIONS_NOT_SATISFIED),
            };

            debug!("Original witness: {:02X?}", original_challenge);
            debug!("Host witness (plaintext): {:02X?}", host_witness);

            // Host should have decrypted our encrypted witness to get the original witness
            if host_witness.as_slice() != original_challenge.as_slice() {
                warn!("Management key authentication failed");
                self.current_challenge = None;
                return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
            }

            // Encrypt host challenge and return in 82 tag
            match TDesOperations::encrypt_ecb(&self.data_objects.management_key, host_challenge) {
                Ok(our_response) => {
                    self.security_state.set_management_key_authenticated(true);
                    self.current_challenge = None;

                    let mut response = vec![0x7C, 0x0A, 0x82, 0x08];
                    response.extend_from_slice(&our_response);
                    info!("Management key authenticated successfully");
                    return Response::success(response);
                }
                Err(_) => {
                    self.current_challenge = None;
                    return Response::error(SW::EXEC_ERROR);
                }
            }
        }

        Response::error(SW::WRONG_DATA)
    }

    /// Sign data with the private key
    fn sign_data(&self, key_data: &PIVKeyData, data: &[u8]) -> Response {
        let algorithm = PIVAlgorithm::from_byte(key_data.algorithm);

        let signature = match algorithm {
            Some(PIVAlgorithm::RSA2048) => {
                // For RSA, need to decode private key and sign
                let n = match RsaOperations::get_modulus(&key_data.public_key) {
                    Some(n) => n,
                    None => return Response::error(SW::EXEC_ERROR),
                };
                let rsa_key = match RsaOperations::decode_private_key(&key_data.private_key, &n) {
                    Ok(key) => key,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                };
                match RsaOperations::raw_sign(&rsa_key, data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            }
            Some(PIVAlgorithm::ECCP256) => {
                match EccNistOperations::sign(EccCurve::P256, &key_data.private_key, data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            }
            Some(PIVAlgorithm::ECCP384) => {
                match EccNistOperations::sign(EccCurve::P384, &key_data.private_key, data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            }
            _ => return Response::error(SW::FUNCTION_NOT_SUPPORTED),
        };

        // Return signature in 7C template with 82 tag
        let response = if signature.len() <= 127 {
            let mut resp = vec![0x7C, (signature.len() + 2) as u8, 0x82, signature.len() as u8];
            resp.extend_from_slice(&signature);
            resp
        } else {
            let mut resp = vec![0x7C, 0x81, (signature.len() + 3) as u8, 0x82, 0x81, signature.len() as u8];
            resp.extend_from_slice(&signature);
            resp
        };

        debug!("Signed {} bytes, signature {} bytes", data.len(), signature.len());
        Response::success(response)
    }

    /// Decrypt data or perform ECDH
    fn decrypt_data(&self, key_data: &PIVKeyData, cipher_text: &[u8]) -> Response {
        let algorithm = PIVAlgorithm::from_byte(key_data.algorithm);

        let plaintext = match algorithm {
            Some(PIVAlgorithm::RSA2048) => {
                let n = match RsaOperations::get_modulus(&key_data.public_key) {
                    Some(n) => n,
                    None => return Response::error(SW::EXEC_ERROR),
                };
                let rsa_key = match RsaOperations::decode_private_key(&key_data.private_key, &n) {
                    Ok(key) => key,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                };
                match RsaOperations::decrypt(&rsa_key, cipher_text) {
                    Ok(pt) => pt,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            }
            Some(PIVAlgorithm::ECCP256) | Some(PIVAlgorithm::ECCP384) => {
                // ECDH not implemented yet
                // TODO: Add ECDH support to ecc_nist module
                return Response::error(SW::FUNCTION_NOT_SUPPORTED);
            }
            _ => return Response::error(SW::FUNCTION_NOT_SUPPORTED),
        };

        // Return result in 7C template with 82 tag
        let response = if plaintext.len() <= 127 {
            let mut resp = vec![0x7C, (plaintext.len() + 2) as u8, 0x82, plaintext.len() as u8];
            resp.extend_from_slice(&plaintext);
            resp
        } else {
            let mut resp = vec![0x7C, 0x81, (plaintext.len() + 3) as u8, 0x82, 0x81, plaintext.len() as u8];
            resp.extend_from_slice(&plaintext);
            resp
        };

        debug!("Decrypted/ECDH result: {} bytes", plaintext.len());
        Response::success(response)
    }

    /// Handle GET RESPONSE command (INS C0)
    fn handle_get_response(&mut self, cmd: &APDU) -> Response {
        if self.response_buffer.is_empty() {
            return Response::error(SW::CONDITIONS_NOT_SATISFIED);
        }

        let le = cmd.le.unwrap_or(256) as usize;
        let remaining = self.response_buffer.len() - self.response_offset;
        let to_send = std::cmp::min(le, remaining);

        let data = self.response_buffer[self.response_offset..self.response_offset + to_send].to_vec();
        self.response_offset += to_send;

        if self.response_offset >= self.response_buffer.len() {
            // All data sent
            self.response_buffer.clear();
            self.response_offset = 0;
            Response::success(data)
        } else {
            // More data available
            let still_remaining = self.response_buffer.len() - self.response_offset;
            Response::more_data(data, std::cmp::min(still_remaining, 255) as u8)
        }
    }

    /// Handle GET VERSION command (INS FD) - Yubico extension
    fn handle_get_version(&self, _cmd: &APDU) -> Response {
        let data = vec![self.version.0, self.version.1, self.version.2];
        Response::success(data)
    }

    /// Handle GET SERIAL command (INS F8) - Yubico extension
    fn handle_get_serial(&self, _cmd: &APDU) -> Response {
        let data = self.serial.to_be_bytes().to_vec();
        Response::success(data)
    }
}

impl Default for PIVApplet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_piv() {
        let mut applet = PIVApplet::new();
        let cmd = APDU {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: PIV_AID.to_vec(),
            le: None,
        };
        let response = applet.process_apdu(&cmd);
        assert!(response.is_okay());
    }

    #[test]
    fn test_verify_pin() {
        let mut applet = PIVApplet::new();

        // First select
        let select_cmd = APDU {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: PIV_AID.to_vec(),
            le: None,
        };
        applet.process_apdu(&select_cmd);

        // Verify PIN
        let mut pin_data = b"123456".to_vec();
        pin_data.extend(vec![0xFF; 2]); // Pad to 8 bytes
        let verify_cmd = APDU {
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x80,
            data: pin_data,
            le: None,
        };
        let response = applet.process_apdu(&verify_cmd);
        assert!(response.is_okay());
    }

    #[test]
    fn test_get_version() {
        let mut applet = PIVApplet::new();
        let cmd = APDU {
            cla: 0x00,
            ins: 0xFD,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        };
        let response = applet.process_apdu(&cmd);
        assert!(response.is_okay());
        assert_eq!(response.data.len(), 3);
        assert_eq!(response.data[0], 5); // Major version
    }

    #[test]
    fn test_get_serial() {
        let mut applet = PIVApplet::new();
        let cmd = APDU {
            cla: 0x00,
            ins: 0xF8,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        };
        let response = applet.process_apdu(&cmd);
        assert!(response.is_okay());
        assert_eq!(response.data.len(), 4);
    }
}
