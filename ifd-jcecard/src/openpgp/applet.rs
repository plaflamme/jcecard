//! OpenPGP Applet implementation
//!
//! Main dispatcher for OpenPGP card commands following OpenPGP Smart Card 3.4 specification.

use log::debug;

use crate::apdu::{APDU, Response, SW, ins, pso};
use crate::card::{CardState, CardDataStore, AlgorithmID, CurveOID};
use crate::tlv::{TLVBuilder, read_list};
use crate::crypto::ed25519::Ed25519Operations;
use crate::crypto::x25519::X25519Operations;
use crate::crypto::rsa::RsaOperations;
use crate::crypto::ecc_nist::{EccNistOperations, EccCurve};
use crate::crypto::secp256k1::Secp256k1Operations;
use crate::crypto::fingerprint;
use super::pin_manager::{PINManager, PINType};
use super::security_state::{SecurityState, SecurityCondition};

/// OpenPGP Application Identifier prefix (RID + PIX prefix)
pub const OPENPGP_AID_PREFIX: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// Access conditions for data objects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCondition {
    Always,
    PW1_81,
    PW1_82,
    PW1Any,
    PW3,
    Never,
}

/// OpenPGP Card Applet
pub struct OpenPGPApplet {
    store: CardDataStore,
    pin_manager: PINManager,
    security_state: SecurityState,
    response_buffer: Vec<u8>,
    response_offset: usize,
    command_buffer: Vec<u8>,
    chaining_ins: Option<u8>,
    /// Current command's Le (expected response length)
    current_le: Option<u32>,
}

impl OpenPGPApplet {
    /// Create a new OpenPGP applet
    pub fn new(store: CardDataStore) -> Self {
        Self {
            store,
            pin_manager: PINManager::new(),
            security_state: SecurityState::new(),
            response_buffer: Vec::new(),
            response_offset: 0,
            command_buffer: Vec::new(),
            chaining_ins: None,
            current_le: None,
        }
    }

    /// Process an APDU command and return the response
    pub fn process_apdu(&mut self, cmd: &APDU) -> Response {
        // Store the Le value for response sizing
        self.current_le = cmd.le;

        // Handle GET_RESPONSE first (for response chaining)
        if cmd.ins == ins::GET_RESPONSE {
            return self.handle_get_response(cmd);
        }

        // Handle command chaining
        if cmd.is_chained() {
            return self.handle_command_chaining(cmd);
        }

        // If we had chained commands, combine them
        let effective_cmd = if !self.command_buffer.is_empty() {
            // Validate INS matches
            if self.chaining_ins != Some(cmd.ins) {
                self.command_buffer.clear();
                self.chaining_ins = None;
                return Response::error(SW::CONDITIONS_NOT_SATISFIED);
            }

            // Combine buffered data with final command data
            let mut combined_data = std::mem::take(&mut self.command_buffer);
            combined_data.extend_from_slice(&cmd.data);
            self.chaining_ins = None;

            APDU {
                cla: cmd.cla & 0xEF, // Clear chaining bit
                ins: cmd.ins,
                p1: cmd.p1,
                p2: cmd.p2,
                data: combined_data,
                le: cmd.le,
            }
        } else {
            cmd.clone()
        };

        // Check if card is terminated
        if self.store.get_state().terminated {
            // Only ACTIVATE_FILE is allowed on terminated card
            if effective_cmd.ins != ins::ACTIVATE_FILE {
                return Response::error(SW::CONDITIONS_NOT_SATISFIED);
            }
        }

        // Route to appropriate handler
        match effective_cmd.ins {
            ins::SELECT => self.handle_select(&effective_cmd),
            ins::GET_DATA => self.handle_get_data(&effective_cmd),
            ins::VERIFY => self.handle_verify(&effective_cmd),
            ins::CHANGE_REFERENCE_DATA => self.handle_change_reference_data(&effective_cmd),
            ins::RESET_RETRY_COUNTER => self.handle_reset_retry_counter(&effective_cmd),
            ins::PUT_DATA => self.handle_put_data(&effective_cmd),
            ins::PUT_DATA_ODD => self.handle_put_data_odd(&effective_cmd),
            ins::GENERATE_ASYMMETRIC_KEY_PAIR => self.handle_generate_key(&effective_cmd),
            ins::PSO => self.handle_pso(&effective_cmd),
            ins::INTERNAL_AUTHENTICATE => self.handle_internal_authenticate(&effective_cmd),
            ins::GET_CHALLENGE => self.handle_get_challenge(&effective_cmd),
            ins::TERMINATE_DF => self.handle_terminate(&effective_cmd),
            ins::ACTIVATE_FILE => self.handle_activate(&effective_cmd),
            _ => Response::error(SW::INS_NOT_SUPPORTED),
        }
    }

    /// Handle command chaining (CLA bit 4 set)
    fn handle_command_chaining(&mut self, cmd: &APDU) -> Response {
        // Start or continue chaining
        if self.chaining_ins.is_none() {
            self.chaining_ins = Some(cmd.ins);
            self.command_buffer.clear();
        } else if self.chaining_ins != Some(cmd.ins) {
            // INS mismatch in chained commands
            self.command_buffer.clear();
            self.chaining_ins = None;
            return Response::error(SW::CONDITIONS_NOT_SATISFIED);
        }

        // Accumulate data
        self.command_buffer.extend_from_slice(&cmd.data);

        // Return success, waiting for more data
        Response::ok()
    }

    /// Handle GET_RESPONSE for response chaining
    fn handle_get_response(&mut self, cmd: &APDU) -> Response {
        if self.response_buffer.is_empty() {
            return Response::error(SW::CONDITIONS_NOT_SATISFIED);
        }

        let le = cmd.le.unwrap_or(256) as usize;
        let remaining = self.response_buffer.len() - self.response_offset;
        let chunk_size = le.min(remaining);

        let data = self.response_buffer[self.response_offset..self.response_offset + chunk_size].to_vec();
        self.response_offset += chunk_size;

        let new_remaining = self.response_buffer.len() - self.response_offset;

        if new_remaining == 0 {
            self.response_buffer.clear();
            self.response_offset = 0;
            Response::success(data)
        } else if new_remaining > 255 {
            Response::more_data(data, 0)
        } else {
            Response::more_data(data, new_remaining as u8)
        }
    }

    /// Create response with chaining if needed
    fn create_response(&mut self, data: Vec<u8>) -> Response {
        // Use the requested Le to determine max response size
        // For extended APDUs, Le can be up to 65536
        // Default to 256 for short APDUs
        let max_response = self.current_le.unwrap_or(256) as usize;

        if data.len() <= max_response {
            Response::success(data)
        } else {
            // Need response chaining
            self.response_buffer = data;
            self.response_offset = max_response;

            let chunk = self.response_buffer[0..max_response].to_vec();
            let remaining = self.response_buffer.len() - max_response;

            if remaining > 255 {
                Response::more_data(chunk, 0)
            } else {
                Response::more_data(chunk, remaining as u8)
            }
        }
    }

    // =========================================================================
    // Command Handlers
    // =========================================================================

    /// Handle SELECT command
    fn handle_select(&mut self, cmd: &APDU) -> Response {
        // P1=0x04 means select by DF name (AID)
        if cmd.p1 != 0x04 {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Check if selecting OpenPGP applet
        if cmd.data.len() >= OPENPGP_AID_PREFIX.len()
            && &cmd.data[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
        {
            // Return success - application data is obtained via GET DATA
            Response::ok()
        } else {
            Response::error(SW::FILE_NOT_FOUND)
        }
    }

    /// Handle GET_DATA command
    fn handle_get_data(&self, cmd: &APDU) -> Response {
        let tag = cmd.p1p2();

        // Check access condition
        let access = Self::get_data_access(tag);
        if !self.check_access(access) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state();

        let data = match tag {
            // Application Identifier
            0x004F => state.get_aid(),

            // Historical bytes
            0x5F52 => state.get_historical_bytes(),

            // Cardholder Related Data (65)
            0x0065 => self.build_cardholder_data(),

            // Application Related Data (6E)
            0x006E => self.build_application_data(),

            // Security Support Template (7A)
            0x007A => self.build_security_support_template(),

            // Extended Capabilities
            0x00C0 => state.get_extended_capabilities(),

            // Algorithm attributes
            0x00C1 => state.key_sig.algorithm.to_bytes(),
            0x00C2 => state.key_dec.algorithm.to_bytes(),
            0x00C3 => state.key_aut.algorithm.to_bytes(),

            // PW Status Bytes
            0x00C4 => state.get_pw_status_bytes(),

            // Fingerprints
            0x00C5 => state.get_fingerprints(),
            0x00C6 => state.get_ca_fingerprints(),
            0x00C7 => state.key_sig.fingerprint_padded(),
            0x00C8 => state.key_dec.fingerprint_padded(),
            0x00C9 => state.key_aut.fingerprint_padded(),
            0x00CA => state.key_sig.ca_fingerprint_padded(),
            0x00CB => state.key_dec.ca_fingerprint_padded(),
            0x00CC => state.key_aut.ca_fingerprint_padded(),

            // Key timestamps
            0x00CD => state.get_key_timestamps(),
            0x00CE => Self::timestamp_to_bytes(state.key_sig.generation_time),
            0x00CF => Self::timestamp_to_bytes(state.key_dec.generation_time),
            0x00D0 => Self::timestamp_to_bytes(state.key_aut.generation_time),

            // Signature counter
            0x0093 => state.get_signature_counter_bytes(),

            // Cardholder name
            0x005B => state.cardholder.name.as_bytes().to_vec(),

            // Language preference
            0x5F2D => state.cardholder.language.as_bytes().to_vec(),

            // Sex
            0x5F35 => vec![state.cardholder.sex],

            // Login data
            0x005E => state.cardholder.login.as_bytes().to_vec(),

            // URL
            0x5F50 => state.cardholder.url.as_bytes().to_vec(),

            // Private DOs
            0x0101 => state.private_do_1.clone(),
            0x0102 => state.private_do_2.clone(),
            0x0103 => state.private_do_3.clone(),
            0x0104 => state.private_do_4.clone(),

            // Cardholder certificate
            0x7F21 => state.certificate.clone(),

            // General Feature Management
            0x7F74 => state.get_general_feature_management(),

            // UIF (User Interaction Flag)
            0x00D6 => vec![state.key_sig.uif, 0x20],
            0x00D7 => vec![state.key_dec.uif, 0x20],
            0x00D8 => vec![state.key_aut.uif, 0x20],

            // Algorithm Information (FA) - lists supported algorithms
            0x00FA => self.build_algorithm_information(),

            _ => return Response::error(SW::REFERENCED_DATA_NOT_FOUND),
        };

        Response::success(data)
    }

    /// Handle VERIFY command
    fn handle_verify(&mut self, cmd: &APDU) -> Response {
        let pin_type = match cmd.p2 {
            0x81 => PINType::PW1_81,
            0x82 => PINType::PW1_82,
            0x83 => PINType::PW3,
            _ => return Response::error(SW::WRONG_P1_P2),
        };

        // Empty data = check status
        if cmd.data.is_empty() {
            let retry_count = self.pin_manager.get_retry_counter(
                pin_type,
                &self.store.get_state().pin_data,
            );

            if retry_count == 0 {
                return Response::error(SW::AUTH_METHOD_BLOCKED);
            }

            // Check if already verified
            let condition = match pin_type {
                PINType::PW1_81 => SecurityCondition::PW1_81,
                PINType::PW1_82 => SecurityCondition::PW1_82,
                PINType::PW3 => SecurityCondition::PW3,
                PINType::RC => return Response::error(SW::WRONG_P1_P2),
            };

            if self.security_state.is_verified(condition) {
                return Response::ok();
            }

            return Response::error(SW::counter_warning(retry_count));
        }

        // Strip padding bytes (0x00, 0xFF)
        let pin: Vec<u8> = cmd.data.iter()
            .copied()
            .filter(|&b| b != 0x00 && b != 0xFF)
            .collect();

        // Verify PIN
        let pin_data = &mut self.store.get_state_mut().pin_data;
        if self.pin_manager.verify_pin(pin_type, &pin, pin_data) {
            // Set security state
            let condition = match pin_type {
                PINType::PW1_81 => SecurityCondition::PW1_81,
                PINType::PW1_82 => SecurityCondition::PW1_82,
                PINType::PW3 => SecurityCondition::PW3,
                PINType::RC => return Response::error(SW::WRONG_P1_P2),
            };
            self.security_state.set_verified(condition);

            // Update PW1 valid multiple from card state
            if matches!(pin_type, PINType::PW1_81 | PINType::PW1_82) {
                self.security_state.set_pw1_valid_multiple(
                    self.store.get_state().pin_data.pw1_valid_multiple
                );
            }

            self.store.save();
            Response::ok()
        } else {
            let retry_count = self.pin_manager.get_retry_counter(
                pin_type,
                &self.store.get_state().pin_data,
            );
            self.store.save();

            if retry_count == 0 {
                Response::error(SW::AUTH_METHOD_BLOCKED)
            } else {
                Response::error(SW::counter_warning(retry_count))
            }
        }
    }

    /// Handle CHANGE_REFERENCE_DATA command
    fn handle_change_reference_data(&mut self, cmd: &APDU) -> Response {
        let pin_type = match cmd.p2 {
            0x81 => PINType::PW1_81,
            0x83 => PINType::PW3,
            _ => return Response::error(SW::WRONG_P1_P2),
        };

        // Split data into old PIN and new PIN
        let pin_data = &self.store.get_state().pin_data;
        let old_len = match pin_type {
            PINType::PW1_81 | PINType::PW1_82 => pin_data.pw1_length as usize,
            PINType::PW3 => pin_data.pw3_length as usize,
            PINType::RC => return Response::error(SW::WRONG_P1_P2),
        };

        if cmd.data.len() <= old_len {
            return Response::error(SW::WRONG_LENGTH);
        }

        let old_pin = &cmd.data[..old_len];
        let new_pin = &cmd.data[old_len..];

        let pin_data = &mut self.store.get_state_mut().pin_data;
        if self.pin_manager.change_pin(pin_type, old_pin, new_pin, pin_data) {
            self.store.save();
            Response::ok()
        } else {
            let retry_count = self.pin_manager.get_retry_counter(
                pin_type,
                &self.store.get_state().pin_data,
            );
            self.store.save();

            if retry_count == 0 {
                Response::error(SW::AUTH_METHOD_BLOCKED)
            } else {
                Response::error(SW::counter_warning(retry_count))
            }
        }
    }

    /// Handle RESET_RETRY_COUNTER command
    fn handle_reset_retry_counter(&mut self, cmd: &APDU) -> Response {
        if cmd.p2 != 0x81 {
            return Response::error(SW::WRONG_P1_P2);
        }

        match cmd.p1 {
            0x00 => {
                // Use Reset Code
                let rc_len = self.store.get_state().pin_data.rc_length as usize;
                if cmd.data.len() <= rc_len {
                    return Response::error(SW::WRONG_LENGTH);
                }
                let reset_code = &cmd.data[..rc_len];
                let new_pin = &cmd.data[rc_len..];

                let pin_data = &mut self.store.get_state_mut().pin_data;
                if self.pin_manager.reset_pw1_with_rc(reset_code, new_pin, pin_data) {
                    self.store.save();
                    Response::ok()
                } else {
                    self.store.save();
                    Response::error(SW::SECURITY_STATUS_NOT_SATISFIED)
                }
            }
            0x02 => {
                // Use PW3
                if !self.security_state.is_verified(SecurityCondition::PW3) {
                    return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
                }

                let pin_data = &mut self.store.get_state_mut().pin_data;
                if self.pin_manager.reset_pw1_with_pw3(&cmd.data, pin_data) {
                    self.store.save();
                    Response::ok()
                } else {
                    Response::error(SW::WRONG_DATA)
                }
            }
            _ => Response::error(SW::WRONG_P1_P2),
        }
    }

    /// Handle PUT_DATA command
    fn handle_put_data(&mut self, cmd: &APDU) -> Response {
        let tag = cmd.p1p2();

        // Check access condition
        let access = Self::put_data_access(tag);
        if !self.check_access(access) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state_mut();

        match tag {
            // Cardholder name
            0x005B => {
                state.cardholder.name = String::from_utf8_lossy(&cmd.data).to_string();
            }

            // Language preference
            0x5F2D => {
                state.cardholder.language = String::from_utf8_lossy(&cmd.data).to_string();
            }

            // Sex
            0x5F35 => {
                if !cmd.data.is_empty() {
                    state.cardholder.sex = cmd.data[0];
                }
            }

            // Login data
            0x005E => {
                state.cardholder.login = String::from_utf8_lossy(&cmd.data).to_string();
            }

            // URL
            0x5F50 => {
                state.cardholder.url = String::from_utf8_lossy(&cmd.data).to_string();
            }

            // Private DOs
            0x0101 => state.private_do_1 = cmd.data.clone(),
            0x0102 => state.private_do_2 = cmd.data.clone(),
            0x0103 => state.private_do_3 = cmd.data.clone(),
            0x0104 => state.private_do_4 = cmd.data.clone(),

            // Algorithm attributes
            0x00C1 => {
                if let Some(attrs) = crate::card::AlgorithmAttributes::from_bytes(&cmd.data) {
                    state.key_sig.algorithm = attrs;
                } else {
                    return Response::error(SW::WRONG_DATA);
                }
            }
            0x00C2 => {
                if let Some(attrs) = crate::card::AlgorithmAttributes::from_bytes(&cmd.data) {
                    state.key_dec.algorithm = attrs;
                } else {
                    return Response::error(SW::WRONG_DATA);
                }
            }
            0x00C3 => {
                if let Some(attrs) = crate::card::AlgorithmAttributes::from_bytes(&cmd.data) {
                    state.key_aut.algorithm = attrs;
                } else {
                    return Response::error(SW::WRONG_DATA);
                }
            }

            // PW Status Bytes (first byte only - pw1 valid for multiple)
            0x00C4 => {
                if !cmd.data.is_empty() {
                    state.pin_data.pw1_valid_multiple = cmd.data[0] != 0;
                }
            }

            // Fingerprints (individual)
            0x00C7 => {
                if cmd.data.len() == 20 {
                    state.key_sig.fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00C8 => {
                if cmd.data.len() == 20 {
                    state.key_dec.fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00C9 => {
                if cmd.data.len() == 20 {
                    state.key_aut.fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }

            // CA Fingerprints
            0x00CA => {
                if cmd.data.len() == 20 {
                    state.key_sig.ca_fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00CB => {
                if cmd.data.len() == 20 {
                    state.key_dec.ca_fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00CC => {
                if cmd.data.len() == 20 {
                    state.key_aut.ca_fingerprint = cmd.data.clone();
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }

            // Generation timestamps
            0x00CE => {
                if cmd.data.len() == 4 {
                    state.key_sig.generation_time = Self::bytes_to_timestamp(&cmd.data);
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00CF => {
                if cmd.data.len() == 4 {
                    state.key_dec.generation_time = Self::bytes_to_timestamp(&cmd.data);
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }
            0x00D0 => {
                if cmd.data.len() == 4 {
                    state.key_aut.generation_time = Self::bytes_to_timestamp(&cmd.data);
                } else {
                    return Response::error(SW::WRONG_LENGTH);
                }
            }

            // Reset Code
            0x00D3 => {
                if cmd.data.is_empty() {
                    // Clear reset code
                    state.pin_data.rc_hash.clear();
                    state.pin_data.rc_length = 0;
                } else {
                    let rc_len = cmd.data.len() as u8;
                    if rc_len < state.pin_data.rc_min_length {
                        return Response::error(SW::WRONG_LENGTH);
                    }
                    state.pin_data.rc_hash = PINManager::hash_pin(&cmd.data);
                    state.pin_data.rc_length = rc_len;
                    state.pin_data.rc_retry_counter = state.pin_data.rc_max_retries;
                }
            }

            // UIF
            0x00D6 => {
                if !cmd.data.is_empty() {
                    state.key_sig.uif = cmd.data[0];
                }
            }
            0x00D7 => {
                if !cmd.data.is_empty() {
                    state.key_dec.uif = cmd.data[0];
                }
            }
            0x00D8 => {
                if !cmd.data.is_empty() {
                    state.key_aut.uif = cmd.data[0];
                }
            }

            // Cardholder certificate
            0x7F21 => {
                state.certificate = cmd.data.clone();
            }

            _ => return Response::error(SW::REFERENCED_DATA_NOT_FOUND),
        }

        self.store.save();
        Response::ok()
    }

    /// Handle PUT_DATA_ODD command (key import)
    fn handle_put_data_odd(&mut self, cmd: &APDU) -> Response {
        // Extended header list format
        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Requires PW3
        if !self.security_state.is_verified(SecurityCondition::PW3) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        self.handle_key_import(&cmd.data)
    }

    /// Handle key import from Extended Header List format
    fn handle_key_import(&mut self, data: &[u8]) -> Response {
        // Parse TLV structure: 4D [CRT] [7F48] [5F48]
        let tlvs = read_list(data, true);
        if tlvs.is_empty() {
            return Response::error(SW::WRONG_DATA);
        }

        // Look for extended header list (4D)
        let header_list = if tlvs[0].tag == 0x4D {
            &tlvs[0]
        } else {
            return Response::error(SW::WRONG_DATA);
        };

        // Note: 4D (Extended Header List) is NOT a "constructed" tag by BER-TLV rules
        // because bit 5 of 0x4D is 0 (0x4D = 0100 1101). However, its value actually
        // contains nested TLV structures (CRT tag B6/B8/A4, 7F48, 5F48). The TLV parser
        // won't automatically populate `subs` for non-constructed tags, so we must
        // explicitly parse the value as a list of TLVs.
        let children = read_list(&header_list.value, true);

        // Find CRT tag to determine key slot
        let key_slot = children.iter()
            .find_map(|tlv| match tlv.tag {
                0xB6 => Some(KeySlotType::Sig),
                0xB8 => Some(KeySlotType::Dec),
                0xA4 => Some(KeySlotType::Aut),
                _ => None,
            });

        let key_slot = match key_slot {
            Some(slot) => slot,
            None => return Response::error(SW::WRONG_DATA),
        };

        // Find concatenated key data (5F48)
        let key_data = children.iter()
            .find(|t| t.tag == 0x5F48)
            .map(|t| t.value.clone());

        let key_data = match key_data {
            Some(data) => data,
            None => return Response::error(SW::WRONG_DATA),
        };

        // Get current algorithm for this slot
        let state = self.store.get_state_mut();
        let slot = match key_slot {
            KeySlotType::Sig => &mut state.key_sig,
            KeySlotType::Dec => &mut state.key_dec,
            KeySlotType::Aut => &mut state.key_aut,
        };

        // Import based on algorithm type
        if slot.algorithm.algorithm_id == AlgorithmID::RSA {
            // RSA key import: parse CRT template (7F48) to get component lengths
            // 7F48 contains: 91 <e_len> 92 <p_len> 93 <q_len>
            // 5F48 contains: e || p || q (concatenated)

            // 7F48 is a constructed tag containing component lengths
            let crt_tag = match children.iter().find(|t| t.tag == 0x7F48) {
                Some(t) => t,
                None => {
                    debug!("RSA key import: 7F48 CRT template not found");
                    return Response::error(SW::WRONG_DATA);
                }
            };

            // Parse CRT template manually - it uses a special format:
            // Tag followed by BER-TLV length encoding (the length IS the component size)
            // Format: 91 <len-e> 92 <len-p> 93 <len-q>
            // where <len-x> is BER-TLV length encoding
            let crt_data = &crt_tag.value;
            let (e_len, p_len, q_len) = Self::parse_crt_lengths(crt_data);
            debug!("RSA key import: parsed lengths e={} p={} q={}", e_len, p_len, q_len);

            if e_len == 0 || p_len == 0 || q_len == 0 {
                debug!("RSA key import: invalid component lengths e={} p={} q={}", e_len, p_len, q_len);
                return Response::error(SW::WRONG_DATA);
            }

            // Verify lengths match
            if key_data.len() != e_len + p_len + q_len {
                debug!("RSA key import: length mismatch {} != {} + {} + {}",
                    key_data.len(), e_len, p_len, q_len);
                return Response::error(SW::WRONG_DATA);
            }

            // Extract components
            let e_bytes = &key_data[0..e_len];
            let p_bytes = &key_data[e_len..e_len + p_len];
            let q_bytes = &key_data[e_len + p_len..];

            // Calculate n = p * q
            use rsa::BigUint;
            let p = BigUint::from_bytes_be(p_bytes);
            let q = BigUint::from_bytes_be(q_bytes);
            let n = &p * &q;
            let n_bytes = n.to_bytes_be();

            // Encode private key data with length prefixes
            // Format: e_len(2) || e || p_len(2) || p || q_len(2) || q
            let mut private_data = Vec::new();
            private_data.extend_from_slice(&(e_len as u16).to_be_bytes());
            private_data.extend_from_slice(e_bytes);
            private_data.extend_from_slice(&(p_len as u16).to_be_bytes());
            private_data.extend_from_slice(p_bytes);
            private_data.extend_from_slice(&(q_len as u16).to_be_bytes());
            private_data.extend_from_slice(q_bytes);
            slot.private_key_data = private_data;

            // Encode public key data in internal format for signing/decryption
            // Format: n_len(2) || n || e_len(2) || e
            let mut public_data = Vec::new();
            public_data.extend_from_slice(&(n_bytes.len() as u16).to_be_bytes());
            public_data.extend_from_slice(&n_bytes);
            public_data.extend_from_slice(&(e_len as u16).to_be_bytes());
            public_data.extend_from_slice(e_bytes);
            slot.public_key_data = public_data;

            debug!("RSA key import: n={} bits, e={} bytes", n_bytes.len() * 8, e_len);
        } else {
            // ECC key import
            let algorithm_id = slot.algorithm.algorithm_id;
            let curve_oid = &slot.algorithm.curve_oid;

            // Determine expected key size based on algorithm and curve
            // P-384 uses 48-byte keys, all other ECC curves use 32-byte keys
            let expected_size = if algorithm_id == AlgorithmID::EDDSA {
                32 // Ed25519
            } else if algorithm_id == AlgorithmID::ECDH || algorithm_id == AlgorithmID::ECDSA {
                if slot.algorithm.is_nistp521() {
                    66 // P-521
                } else if slot.algorithm.is_nistp384() {
                    48 // P-384
                } else if slot.algorithm.is_x25519() || slot.algorithm.is_nistp256() || slot.algorithm.is_secp256k1() {
                    32 // X25519, P-256, or secp256k1
                } else {
                    return Response::error(SW::WRONG_DATA);
                }
            } else {
                return Response::error(SW::WRONG_DATA);
            };

            if key_data.len() != expected_size {
                debug!("ECC key import: wrong key size {} (expected {})", key_data.len(), expected_size);
                return Response::error(SW::WRONG_DATA);
            }

            // For X25519 keys: OpenPGP uses MPI format (big-endian), but x25519-dalek
            // expects native little-endian format. We reverse the bytes on import.
            let stored_key = if algorithm_id == AlgorithmID::ECDH && slot.algorithm.is_x25519() {
                key_data.iter().rev().cloned().collect::<Vec<u8>>()
            } else {
                key_data.clone()
            };
            slot.private_key_data = stored_key.clone();

            // Generate public key based on algorithm type
            let public_key_result = if algorithm_id == AlgorithmID::EDDSA {
                Ed25519Operations::get_public_key(&key_data).ok()
            } else if algorithm_id == AlgorithmID::ECDH {
                if slot.algorithm.is_x25519() {
                    X25519Operations::get_public_key(&stored_key).ok()
                } else if slot.algorithm.is_nistp256() {
                    EccNistOperations::get_public_key(EccCurve::P256, &key_data).ok()
                } else if slot.algorithm.is_nistp384() {
                    EccNistOperations::get_public_key(EccCurve::P384, &key_data).ok()
                } else if slot.algorithm.is_nistp521() {
                    EccNistOperations::get_public_key(EccCurve::P521, &key_data).ok()
                } else if slot.algorithm.is_secp256k1() {
                    Secp256k1Operations::get_public_key(&key_data).ok()
                } else {
                    None
                }
            } else if algorithm_id == AlgorithmID::ECDSA {
                if slot.algorithm.is_nistp256() {
                    EccNistOperations::get_public_key(EccCurve::P256, &key_data).ok()
                } else if slot.algorithm.is_nistp384() {
                    EccNistOperations::get_public_key(EccCurve::P384, &key_data).ok()
                } else if slot.algorithm.is_nistp521() {
                    EccNistOperations::get_public_key(EccCurve::P521, &key_data).ok()
                } else if slot.algorithm.is_secp256k1() {
                    Secp256k1Operations::get_public_key(&key_data).ok()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(public_key) = public_key_result {
                let pub_key_tlv = TLVBuilder::new()
                    .add(0x86, &public_key)
                    .wrap(0x7F49)
                    .build();
                slot.public_key_data = pub_key_tlv;
                debug!("ECC key import: generated public key {} bytes for curve {:?}",
                       public_key.len(), CurveOID::name(curve_oid));
            } else {
                debug!("ECC key import: failed to generate public key");
                return Response::error(SW::EXEC_ERROR);
            }

            // Note: Fingerprint and timestamp are set by the client via PUT DATA
            // (tags 0x00C7/C8/C9 for fingerprints, 0x00CE/CF/D0 for timestamps).
            // We do NOT calculate them here - the client provides the correct values
            // that match the OpenPGP key's fingerprint.
        }

        self.store.save();
        Response::ok()
    }

    /// Handle GENERATE_ASYMMETRIC_KEY_PAIR command
    fn handle_generate_key(&mut self, cmd: &APDU) -> Response {
        // P1: 0x80 = generate, 0x81 = read existing public key
        let generate = cmd.p1 == 0x80;

        if cmd.p1 != 0x80 && cmd.p1 != 0x81 {
            return Response::error(SW::WRONG_P1_P2);
        }

        // Parse CRT tag from data to determine key slot
        let key_slot = if cmd.data.is_empty() {
            return Response::error(SW::WRONG_DATA);
        } else {
            match cmd.data[0] {
                0xB6 => KeySlotType::Sig,
                0xB8 => KeySlotType::Dec,
                0xA4 => KeySlotType::Aut,
                _ => return Response::error(SW::WRONG_DATA),
            }
        };

        // Generate requires PW3
        if generate && !self.security_state.is_verified(SecurityCondition::PW3) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state_mut();
        let slot = match key_slot {
            KeySlotType::Sig => &mut state.key_sig,
            KeySlotType::Dec => &mut state.key_dec,
            KeySlotType::Aut => &mut state.key_aut,
        };

        if generate {
            // Generate new key pair
            let algorithm = &slot.algorithm;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);

            // For RSA, we need to handle storage format differently:
            // - Store raw format (n_len||n||e_len||e) in slot.public_key_data
            // - Return TLV format (7F49{81{n}82{e}}) in the response
            let (private_key, public_key_for_storage, response_tlv) = if algorithm.algorithm_id == AlgorithmID::RSA {
                // Generate RSA key
                let bits = algorithm.param1 as usize;
                match RsaOperations::generate_keypair(bits) {
                    Ok((priv_key, pub_key_data)) => {
                        // Extract n and e from public key data (raw format)
                        let n = RsaOperations::get_modulus(&pub_key_data).unwrap_or_default();
                        let e = RsaOperations::get_exponent(&pub_key_data).unwrap_or_default();
                        // Encode public key as 7F49 template for response
                        let pub_tlv = TLVBuilder::new()
                            .add(0x81, &n)
                            .add(0x82, &e)
                            .wrap(0x7F49)
                            .build();
                        // Store raw format, return TLV format
                        (priv_key, pub_key_data, pub_tlv)
                    }
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.algorithm_id == AlgorithmID::EDDSA {
                // Generate Ed25519 key
                match Ed25519Operations::generate_keypair() {
                    Ok((priv_key, pub_key)) => {
                        let pub_tlv = TLVBuilder::new()
                            .add(0x86, &pub_key)
                            .wrap(0x7F49)
                            .build();
                        // Ed25519 stores TLV format (same for storage and response)
                        (priv_key, pub_tlv.clone(), pub_tlv)
                    }
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.algorithm_id == AlgorithmID::ECDH {
                // Generate ECDH key based on curve
                if algorithm.is_x25519() {
                    // Generate X25519 key
                    match X25519Operations::generate_keypair() {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_nistp256() {
                    // Generate P-256 ECDH key
                    match EccNistOperations::generate_keypair(EccCurve::P256) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_nistp384() {
                    // Generate P-384 ECDH key
                    match EccNistOperations::generate_keypair(EccCurve::P384) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_nistp521() {
                    // Generate P-521 ECDH key
                    match EccNistOperations::generate_keypair(EccCurve::P521) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_secp256k1() {
                    // Generate secp256k1 ECDH key
                    match Secp256k1Operations::generate_keypair() {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else {
                    return Response::error(SW::FUNCTION_NOT_SUPPORTED);
                }
            } else if algorithm.algorithm_id == AlgorithmID::ECDSA {
                // Generate ECDSA key based on curve
                if algorithm.is_nistp256() {
                    match EccNistOperations::generate_keypair(EccCurve::P256) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_nistp384() {
                    match EccNistOperations::generate_keypair(EccCurve::P384) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_nistp521() {
                    match EccNistOperations::generate_keypair(EccCurve::P521) {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else if algorithm.is_secp256k1() {
                    match Secp256k1Operations::generate_keypair() {
                        Ok((priv_key, pub_key)) => {
                            let pub_tlv = TLVBuilder::new()
                                .add(0x86, &pub_key)
                                .wrap(0x7F49)
                                .build();
                            (priv_key, pub_tlv.clone(), pub_tlv)
                        }
                        Err(_) => return Response::error(SW::EXEC_ERROR),
                    }
                } else {
                    return Response::error(SW::FUNCTION_NOT_SUPPORTED);
                }
            } else {
                return Response::error(SW::FUNCTION_NOT_SUPPORTED);
            };

            // Store key data
            slot.private_key_data = private_key;
            slot.public_key_data = public_key_for_storage;
            slot.generation_time = timestamp;

            // Calculate fingerprint based on algorithm
            // Extract public key from TLV if stored in TLV format
            let extract_pubkey_from_tlv = |data: &[u8]| -> Option<Vec<u8>> {
                let tlvs = read_list(data, true);
                tlvs.iter()
                    .find(|t| t.tag == 0x7F49)
                    .and_then(|t| {
                        let inner = read_list(&t.value, true);
                        inner.iter().find(|pt| pt.tag == 0x86).map(|pt| pt.value.clone())
                    })
            };

            slot.fingerprint = match algorithm.algorithm_id {
                AlgorithmID::RSA => {
                    if let (Some(n), Some(e)) = (
                        RsaOperations::get_modulus(&slot.public_key_data),
                        RsaOperations::get_exponent(&slot.public_key_data),
                    ) {
                        fingerprint::calculate_fingerprint_rsa(&n, &e, timestamp)
                    } else {
                        Vec::new()
                    }
                }
                AlgorithmID::EDDSA => {
                    // Extract Ed25519 public key from TLV
                    if let Some(pub_key) = extract_pubkey_from_tlv(&slot.public_key_data) {
                        fingerprint::calculate_fingerprint_eddsa(&pub_key, timestamp)
                    } else {
                        Vec::new()
                    }
                }
                AlgorithmID::ECDH => {
                    // Extract public key from TLV
                    if let Some(pub_key) = extract_pubkey_from_tlv(&slot.public_key_data) {
                        if algorithm.is_x25519() {
                            fingerprint::calculate_fingerprint_ecdh_x25519(&pub_key, timestamp)
                        } else {
                            // For NIST curves and secp256k1 ECDH, use ECDH fingerprint (algorithm 18)
                            fingerprint::calculate_fingerprint_ecdh(&pub_key, &algorithm.curve_oid, timestamp)
                        }
                    } else {
                        Vec::new()
                    }
                }
                AlgorithmID::ECDSA => {
                    // Extract ECDSA public key from TLV
                    if let Some(pub_key) = extract_pubkey_from_tlv(&slot.public_key_data) {
                        fingerprint::calculate_fingerprint_ecdsa(&pub_key, &algorithm.curve_oid, timestamp)
                    } else {
                        Vec::new()
                    }
                }
                _ => Vec::new(),
            };

            self.store.save();
            self.create_response(response_tlv)
        } else {
            // Return existing public key
            let public_key_data = slot.public_key_data.clone();
            if public_key_data.is_empty() {
                Response::error(SW::REFERENCED_DATA_NOT_FOUND)
            } else {
                // For RSA keys, wrap internal format in 7F49 TLV
                // Ed25519/X25519 are already stored in 7F49 format
                let response_data = if slot.algorithm.algorithm_id == AlgorithmID::RSA {
                    // Extract n and e from internal format
                    if let (Some(n), Some(e)) = (
                        RsaOperations::get_modulus(&public_key_data),
                        RsaOperations::get_exponent(&public_key_data),
                    ) {
                        TLVBuilder::new()
                            .add(0x81, &n)
                            .add(0x82, &e)
                            .wrap(0x7F49)
                            .build()
                    } else {
                        return Response::error(SW::EXEC_ERROR);
                    }
                } else {
                    // Ed25519/X25519 already in 7F49 format
                    public_key_data
                };
                self.create_response(response_data)
            }
        }
    }

    /// Handle PSO (Perform Security Operation) command
    fn handle_pso(&mut self, cmd: &APDU) -> Response {
        match cmd.p1p2() {
            pso::CDS => self.handle_pso_sign(cmd),
            pso::DECIPHER => self.handle_pso_decipher(cmd),
            _ => Response::error(SW::WRONG_P1_P2),
        }
    }

    /// Handle PSO: Compute Digital Signature
    fn handle_pso_sign(&mut self, cmd: &APDU) -> Response {
        // Requires PW1 mode 81
        if !self.security_state.is_verified(SecurityCondition::PW1_81) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state();

        // Check if signature key exists
        if !state.key_sig.has_key() {
            return Response::error(SW::REFERENCED_DATA_NOT_FOUND);
        }

        let algorithm = &state.key_sig.algorithm;
        let private_key_data = &state.key_sig.private_key_data;
        let public_key_data = &state.key_sig.public_key_data;

        // Perform signing
        let signature = if algorithm.algorithm_id == AlgorithmID::RSA {
            // For RSA, need to decode private key first
            let n = match RsaOperations::get_modulus(public_key_data) {
                Some(n) => n,
                None => return Response::error(SW::EXEC_ERROR),
            };
            let rsa_key = match RsaOperations::decode_private_key(private_key_data, &n) {
                Ok(key) => key,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            };
            // cmd.data contains DigestInfo - apply PKCS#1 v1.5 padding and sign
            match RsaOperations::sign_pkcs1v15(&rsa_key, &cmd.data) {
                Ok(sig) => sig,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            }
        } else if algorithm.algorithm_id == AlgorithmID::EDDSA {
            match Ed25519Operations::sign(private_key_data, &cmd.data) {
                Ok(sig) => sig,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            }
        } else if algorithm.algorithm_id == AlgorithmID::ECDSA {
            // ECDSA signing for NIST curves and secp256k1
            if algorithm.is_nistp256() {
                match EccNistOperations::sign(EccCurve::P256, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_nistp384() {
                match EccNistOperations::sign(EccCurve::P384, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_nistp521() {
                match EccNistOperations::sign(EccCurve::P521, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_secp256k1() {
                match Secp256k1Operations::sign(private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else {
                return Response::error(SW::FUNCTION_NOT_SUPPORTED);
            }
        } else {
            return Response::error(SW::FUNCTION_NOT_SUPPORTED);
        };

        // Increment signature counter
        let state = self.store.get_state_mut();
        state.signature_counter = state.signature_counter.saturating_add(1);
        self.store.save();

        // Handle PW1 single-use mode
        self.security_state.after_sign();

        self.create_response(signature)
    }

    /// Handle PSO: Decipher
    fn handle_pso_decipher(&mut self, cmd: &APDU) -> Response {
        // Requires PW1 mode 82
        if !self.security_state.is_verified(SecurityCondition::PW1_82) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state();

        // Check if decryption key exists
        if !state.key_dec.has_key() {
            return Response::error(SW::REFERENCED_DATA_NOT_FOUND);
        }

        if cmd.data.is_empty() {
            return Response::error(SW::WRONG_DATA);
        }

        let algorithm = &state.key_dec.algorithm;
        let private_key_data = &state.key_dec.private_key_data;
        let public_key_data = &state.key_dec.public_key_data;

        // First byte is padding indicator
        let padding_indicator = cmd.data[0];
        let cipher_data = &cmd.data[1..];

        debug!("PSO DECIPHER: padding={:02X}, cipher_data len={}, private_key len={}, public_key len={}",
            padding_indicator, cipher_data.len(), private_key_data.len(), public_key_data.len());

        let plaintext = if padding_indicator == 0x00 {
            // RSA PKCS#1 v1.5
            if algorithm.algorithm_id != AlgorithmID::RSA {
                debug!("PSO DECIPHER: Wrong algorithm for RSA decryption");
                return Response::error(SW::WRONG_DATA);
            }
            // Decode RSA private key
            let n = match RsaOperations::get_modulus(public_key_data) {
                Some(n) => {
                    debug!("PSO DECIPHER: Got modulus n, len={}", n.len());
                    n
                }
                None => {
                    debug!("PSO DECIPHER: Failed to get modulus from public key");
                    return Response::error(SW::EXEC_ERROR);
                }
            };
            let rsa_key = match RsaOperations::decode_private_key(private_key_data, &n) {
                Ok(key) => {
                    debug!("PSO DECIPHER: Decoded RSA private key successfully");
                    key
                }
                Err(e) => {
                    debug!("PSO DECIPHER: Failed to decode private key: {:?}", e);
                    return Response::error(SW::EXEC_ERROR);
                }
            };
            match RsaOperations::decrypt(&rsa_key, cipher_data) {
                Ok(pt) => {
                    debug!("PSO DECIPHER: Decryption succeeded, plaintext len={}", pt.len());
                    pt
                }
                Err(e) => {
                    debug!("PSO DECIPHER: Decryption failed: {:?}", e);
                    return Response::error(SW::EXEC_ERROR);
                }
            }
        } else if padding_indicator == 0xA6 {
            // ECDH (X25519, NIST curves, or secp256k1)
            if algorithm.algorithm_id != AlgorithmID::ECDH {
                return Response::error(SW::WRONG_DATA);
            }

            // Parse ephemeral public key from TLV structure
            // Data format: A6 <len> 7F49 <len> 86 <len> <ephemeral_pubkey>
            // cipher_data still includes the length byte after A6, so parse the whole cmd.data
            let tlvs = read_list(&cmd.data, true);

            // Find A6 tag and parse its value
            let a6_value = match tlvs.iter().find(|t| t.tag == 0xA6) {
                Some(t) => &t.value,
                None => return Response::error(SW::WRONG_DATA),
            };

            // Parse the content of A6 to find 7F49
            let inner_tlvs = read_list(a6_value, true);
            let ephemeral_pubkey = inner_tlvs.iter()
                .find(|t| t.tag == 0x7F49)
                .and_then(|t| {
                    // 7F49 is constructed, parse its value to find 86
                    let pub_key_tlvs = read_list(&t.value, true);
                    pub_key_tlvs.iter().find(|pt| pt.tag == 0x86).map(|pt| pt.value.clone())
                });

            let ephemeral_pubkey = match ephemeral_pubkey {
                Some(pk) => pk,
                None => return Response::error(SW::WRONG_DATA),
            };

            // Perform ECDH based on curve
            if algorithm.is_x25519() {
                if ephemeral_pubkey.len() != 32 {
                    return Response::error(SW::WRONG_DATA);
                }
                match X25519Operations::ecdh(private_key_data, &ephemeral_pubkey) {
                    Ok(shared_secret) => shared_secret,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_nistp256() {
                // P-256 public key: 65 bytes (0x04 || x || y)
                if ephemeral_pubkey.len() != 65 {
                    debug!("PSO DECIPHER: Invalid P-256 ephemeral pubkey len: {}", ephemeral_pubkey.len());
                    return Response::error(SW::WRONG_DATA);
                }
                match EccNistOperations::ecdh(EccCurve::P256, private_key_data, &ephemeral_pubkey) {
                    Ok(shared_secret) => shared_secret,
                    Err(e) => {
                        debug!("PSO DECIPHER: P-256 ECDH failed: {:?}", e);
                        return Response::error(SW::EXEC_ERROR);
                    }
                }
            } else if algorithm.is_nistp384() {
                // P-384 public key: 97 bytes (0x04 || x || y)
                if ephemeral_pubkey.len() != 97 {
                    debug!("PSO DECIPHER: Invalid P-384 ephemeral pubkey len: {}", ephemeral_pubkey.len());
                    return Response::error(SW::WRONG_DATA);
                }
                match EccNistOperations::ecdh(EccCurve::P384, private_key_data, &ephemeral_pubkey) {
                    Ok(shared_secret) => shared_secret,
                    Err(e) => {
                        debug!("PSO DECIPHER: P-384 ECDH failed: {:?}", e);
                        return Response::error(SW::EXEC_ERROR);
                    }
                }
            } else if algorithm.is_nistp521() {
                // P-521 public key: 133 bytes (0x04 || x || y)
                if ephemeral_pubkey.len() != 133 {
                    debug!("PSO DECIPHER: Invalid P-521 ephemeral pubkey len: {}", ephemeral_pubkey.len());
                    return Response::error(SW::WRONG_DATA);
                }
                match EccNistOperations::ecdh(EccCurve::P521, private_key_data, &ephemeral_pubkey) {
                    Ok(shared_secret) => shared_secret,
                    Err(e) => {
                        debug!("PSO DECIPHER: P-521 ECDH failed: {:?}", e);
                        return Response::error(SW::EXEC_ERROR);
                    }
                }
            } else if algorithm.is_secp256k1() {
                // secp256k1 public key: 65 bytes (0x04 || x || y)
                if ephemeral_pubkey.len() != 65 {
                    debug!("PSO DECIPHER: Invalid secp256k1 ephemeral pubkey len: {}", ephemeral_pubkey.len());
                    return Response::error(SW::WRONG_DATA);
                }
                match Secp256k1Operations::ecdh(private_key_data, &ephemeral_pubkey) {
                    Ok(shared_secret) => shared_secret,
                    Err(e) => {
                        debug!("PSO DECIPHER: secp256k1 ECDH failed: {:?}", e);
                        return Response::error(SW::EXEC_ERROR);
                    }
                }
            } else {
                return Response::error(SW::FUNCTION_NOT_SUPPORTED);
            }
        } else {
            return Response::error(SW::WRONG_DATA);
        };

        self.create_response(plaintext)
    }

    /// Handle INTERNAL_AUTHENTICATE command
    fn handle_internal_authenticate(&mut self, cmd: &APDU) -> Response {
        // Requires PW1 mode 82
        if !self.security_state.is_verified(SecurityCondition::PW1_82) {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        let state = self.store.get_state();

        // Check if authentication key exists
        if !state.key_aut.has_key() {
            return Response::error(SW::REFERENCED_DATA_NOT_FOUND);
        }

        let algorithm = &state.key_aut.algorithm;
        let private_key_data = &state.key_aut.private_key_data;
        let public_key_data = &state.key_aut.public_key_data;

        // Perform signing (same as PSO sign but with auth key)
        let signature = if algorithm.algorithm_id == AlgorithmID::RSA {
            // For RSA, need to decode private key first
            let n = match RsaOperations::get_modulus(public_key_data) {
                Some(n) => n,
                None => return Response::error(SW::EXEC_ERROR),
            };
            let rsa_key = match RsaOperations::decode_private_key(private_key_data, &n) {
                Ok(key) => key,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            };
            match RsaOperations::raw_sign(&rsa_key, &cmd.data) {
                Ok(sig) => sig,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            }
        } else if algorithm.algorithm_id == AlgorithmID::EDDSA {
            match Ed25519Operations::sign(private_key_data, &cmd.data) {
                Ok(sig) => sig,
                Err(_) => return Response::error(SW::EXEC_ERROR),
            }
        } else if algorithm.algorithm_id == AlgorithmID::ECDSA {
            // ECDSA signing for NIST curves and secp256k1
            if algorithm.is_nistp256() {
                match EccNistOperations::sign(EccCurve::P256, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_nistp384() {
                match EccNistOperations::sign(EccCurve::P384, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_nistp521() {
                match EccNistOperations::sign(EccCurve::P521, private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else if algorithm.is_secp256k1() {
                match Secp256k1Operations::sign(private_key_data, &cmd.data) {
                    Ok(sig) => sig,
                    Err(_) => return Response::error(SW::EXEC_ERROR),
                }
            } else {
                return Response::error(SW::FUNCTION_NOT_SUPPORTED);
            }
        } else {
            return Response::error(SW::FUNCTION_NOT_SUPPORTED);
        };

        self.create_response(signature)
    }

    /// Handle GET_CHALLENGE command
    fn handle_get_challenge(&self, cmd: &APDU) -> Response {
        let length = cmd.le.unwrap_or(8) as usize;
        let max_len = 255;

        if length > max_len {
            return Response::error(SW::WRONG_LENGTH);
        }

        let mut challenge = vec![0u8; length];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut challenge);

        Response::success(challenge)
    }

    /// Handle TERMINATE_DF command
    fn handle_terminate(&mut self, _cmd: &APDU) -> Response {
        // Allowed if PW3 verified OR both PW1 and PW3 blocked
        let state = &self.store.get_state().pin_data;
        let pw1_blocked = state.pw1_retry_counter == 0;
        let pw3_blocked = state.pw3_retry_counter == 0;
        let both_blocked = pw1_blocked && pw3_blocked;

        if !self.security_state.is_verified(SecurityCondition::PW3) && !both_blocked {
            return Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        }

        self.store.get_state_mut().terminated = true;
        self.store.save();

        Response::ok()
    }

    /// Handle ACTIVATE_FILE command
    fn handle_activate(&mut self, _cmd: &APDU) -> Response {
        // Reset card to factory defaults
        self.store.reset_to_factory();
        self.security_state.clear_all();
        self.response_buffer.clear();
        self.response_offset = 0;
        self.command_buffer.clear();
        self.chaining_ins = None;

        Response::ok()
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Build Cardholder Related Data (65)
    fn build_cardholder_data(&self) -> Vec<u8> {
        let state = self.store.get_state();

        TLVBuilder::new()
            .add(0x5B, state.cardholder.name.as_bytes())
            .add(0x5F2D, state.cardholder.language.as_bytes())
            .add(0x5F35, &[state.cardholder.sex])
            .wrap(0x65)
            .build()
    }

    /// Build Application Related Data (6E)
    fn build_application_data(&self) -> Vec<u8> {
        let state = self.store.get_state();

        // Build discretionary data objects (73)
        let discretionary = TLVBuilder::new()
            .add(0xC0, &state.get_extended_capabilities())
            .add(0xC1, &state.key_sig.algorithm.to_bytes())
            .add(0xC2, &state.key_dec.algorithm.to_bytes())
            .add(0xC3, &state.key_aut.algorithm.to_bytes())
            .add(0xC4, &state.get_pw_status_bytes())
            .add(0xC5, &state.get_fingerprints())
            .add(0xC6, &state.get_ca_fingerprints())
            .add(0xCD, &state.get_key_timestamps())
            .wrap(0x73)
            .build();

        // Build 7F74 (General Feature Management) - must be inside 6E per real Yubikey behavior
        let gfm = TLVBuilder::new()
            .add_raw(&state.get_general_feature_management())
            .wrap(0x7F74)
            .build();

        TLVBuilder::new()
            .add(0x4F, &state.get_aid())
            .add(0x5F52, &state.get_historical_bytes())
            .add_raw(&gfm)
            .add_raw(&discretionary)
            .wrap(0x6E)
            .build()
    }

    /// Build Security Support Template (7A)
    fn build_security_support_template(&self) -> Vec<u8> {
        let state = self.store.get_state();

        TLVBuilder::new()
            .add(0x93, &state.get_signature_counter_bytes())
            .wrap(0x7A)
            .build()
    }

    /// Build Algorithm Information (FA)
    /// Lists all supported algorithms for each key slot
    fn build_algorithm_information(&self) -> Vec<u8> {
        use crate::card::AlgorithmAttributes;

        // Algorithm attributes for each supported algorithm
        let rsa_2048 = AlgorithmAttributes::rsa(2048).to_bytes();
        let rsa_3072 = AlgorithmAttributes::rsa(3072).to_bytes();
        let rsa_4096 = AlgorithmAttributes::rsa(4096).to_bytes();
        let eddsa = AlgorithmAttributes::ed25519().to_bytes();
        let ecdsa_p256 = AlgorithmAttributes::nistp256_ecdsa().to_bytes();
        let ecdsa_p384 = AlgorithmAttributes::nistp384_ecdsa().to_bytes();
        let ecdsa_p521 = AlgorithmAttributes::nistp521_ecdsa().to_bytes();
        let ecdsa_secp256k1 = AlgorithmAttributes::secp256k1_ecdsa().to_bytes();
        let ecdh_x25519 = AlgorithmAttributes::x25519().to_bytes();
        let ecdh_p256 = AlgorithmAttributes::nistp256_ecdh().to_bytes();
        let ecdh_p384 = AlgorithmAttributes::nistp384_ecdh().to_bytes();
        let ecdh_p521 = AlgorithmAttributes::nistp521_ecdh().to_bytes();
        let ecdh_secp256k1 = AlgorithmAttributes::secp256k1_ecdh().to_bytes();

        // Build flat list of (key_type_tag, length, algo_data) entries.
        // Each algorithm is a separate TLV entry — NOT grouped by key type.
        // This matches the Gnuk/FOSS-Store format that openpgp-card expects.
        let mut data = Vec::new();

        // Helper to append one entry: key_type_tag + length + algo_bytes
        let mut add_entry = |tag: u8, algo: &[u8]| {
            data.push(tag);
            data.push(algo.len() as u8);
            data.extend_from_slice(algo);
        };

        // Signature key algorithms (C1)
        let sig_algos: &[&[u8]] = &[
            &rsa_2048, &rsa_3072, &rsa_4096,
            &eddsa, &ecdsa_p256, &ecdsa_p384, &ecdsa_p521, &ecdsa_secp256k1,
        ];
        for algo in sig_algos {
            add_entry(0xC1, algo);
        }

        // Decryption key algorithms (C2)
        let dec_algos: &[&[u8]] = &[
            &rsa_2048, &rsa_3072, &rsa_4096,
            &ecdh_x25519, &ecdh_p256, &ecdh_p384, &ecdh_p521, &ecdh_secp256k1,
        ];
        for algo in dec_algos {
            add_entry(0xC2, algo);
        }

        // Authentication key algorithms (C3) — same as signature
        let aut_algos: &[&[u8]] = &[
            &rsa_2048, &rsa_3072, &rsa_4096,
            &eddsa, &ecdsa_p256, &ecdsa_p384, &ecdsa_p521, &ecdsa_secp256k1,
        ];
        for algo in aut_algos {
            add_entry(0xC3, algo);
        }

        data
    }

    /// Check access condition
    fn check_access(&self, condition: AccessCondition) -> bool {
        match condition {
            AccessCondition::Always => true,
            AccessCondition::PW1_81 => self.security_state.is_verified(SecurityCondition::PW1_81),
            AccessCondition::PW1_82 => self.security_state.is_verified(SecurityCondition::PW1_82),
            AccessCondition::PW1Any => {
                self.security_state.is_verified(SecurityCondition::PW1_81) ||
                self.security_state.is_verified(SecurityCondition::PW1_82)
            }
            AccessCondition::PW3 => self.security_state.is_verified(SecurityCondition::PW3),
            AccessCondition::Never => false,
        }
    }

    /// Get access condition for GET_DATA tag
    fn get_data_access(tag: u16) -> AccessCondition {
        match tag {
            // Always accessible
            0x004F | 0x5F52 | 0x0065 | 0x006E | 0x007A |
            0x00C0 | 0x00C1 | 0x00C2 | 0x00C3 | 0x00C4 |
            0x00C5 | 0x00C6 | 0x00C7 | 0x00C8 | 0x00C9 |
            0x00CA | 0x00CB | 0x00CC | 0x00CD | 0x00CE |
            0x00CF | 0x00D0 | 0x0093 | 0x005B | 0x5F2D |
            0x5F35 | 0x7F74 | 0x00D6 | 0x00D7 | 0x00D8 |
            0x00FA => AccessCondition::Always,  // Algorithm Information

            // Require PW1 (any mode)
            0x005E | 0x5F50 => AccessCondition::Always,

            // Private DOs - readable without PIN (write still requires PIN)
            // This matches real Yubikey behavior for empty DOs during LEARN
            0x0101..=0x0104 => AccessCondition::Always,

            // Certificate - always
            0x7F21 => AccessCondition::Always,

            _ => AccessCondition::Never,
        }
    }

    /// Get access condition for PUT_DATA tag
    fn put_data_access(tag: u16) -> AccessCondition {
        match tag {
            // Cardholder data - require PW3
            0x005B | 0x5F2D | 0x5F35 | 0x005E | 0x5F50 => AccessCondition::PW3,

            // Algorithm attributes - require PW3
            0x00C1..=0x00C3 => AccessCondition::PW3,

            // PW status bytes - require PW3
            0x00C4 => AccessCondition::PW3,

            // Fingerprints - require PW3
            0x00C7..=0x00CC => AccessCondition::PW3,

            // Timestamps - require PW3
            0x00CE..=0x00D0 => AccessCondition::PW3,

            // Private DOs 1-2 require PW1, 3-4 require PW3
            0x0101 | 0x0102 => AccessCondition::PW1Any,
            0x0103 | 0x0104 => AccessCondition::PW3,

            // Reset code, UIF - require PW3
            0x00D3 | 0x00D6 | 0x00D7 | 0x00D8 => AccessCondition::PW3,

            // Certificate - require PW3
            0x7F21 => AccessCondition::PW3,

            _ => AccessCondition::Never,
        }
    }

    /// Convert timestamp to 4 bytes
    fn timestamp_to_bytes(ts: u32) -> Vec<u8> {
        vec![
            (ts >> 24) as u8,
            (ts >> 16) as u8,
            (ts >> 8) as u8,
            ts as u8,
        ]
    }

    /// Convert 4 bytes to timestamp
    fn bytes_to_timestamp(data: &[u8]) -> u32 {
        if data.len() >= 4 {
            ((data[0] as u32) << 24) |
            ((data[1] as u32) << 16) |
            ((data[2] as u32) << 8) |
            (data[3] as u32)
        } else {
            0
        }
    }

    /// Get a reference to the card state
    pub fn get_state(&self) -> &CardState {
        self.store.get_state()
    }

    /// Get a mutable reference to the card state
    pub fn get_state_mut(&mut self) -> &mut CardState {
        self.store.get_state_mut()
    }

    /// Save the current state
    pub fn save(&self) -> bool {
        self.store.save()
    }

    /// Reset security state (on card reset)
    pub fn reset(&mut self) {
        self.security_state.clear_all();
        self.response_buffer.clear();
        self.response_offset = 0;
        self.command_buffer.clear();
        self.chaining_ins = None;
    }

    /// Parse CRT template lengths for RSA key import
    /// Format: 91 <ber-len-e> 92 <ber-len-p> 93 <ber-len-q>
    /// where <ber-len-x> is BER-TLV length encoding (the length value IS the component size)
    fn parse_crt_lengths(data: &[u8]) -> (usize, usize, usize) {
        let mut e_len = 0usize;
        let mut p_len = 0usize;
        let mut q_len = 0usize;

        let mut offset = 0;
        while offset < data.len() {
            let tag = data[offset];
            offset += 1;

            if offset >= data.len() {
                break;
            }

            // Parse BER-TLV length (this IS the component size)
            let (length, len_bytes) = Self::parse_ber_length(&data[offset..]);
            offset += len_bytes;

            match tag {
                0x91 => e_len = length,
                0x92 => p_len = length,
                0x93 => q_len = length,
                _ => {}
            }
        }

        (e_len, p_len, q_len)
    }

    /// Parse BER-TLV length encoding
    /// Returns (length_value, bytes_consumed)
    fn parse_ber_length(data: &[u8]) -> (usize, usize) {
        if data.is_empty() {
            return (0, 0);
        }

        let first = data[0];

        // Short form: 0-127
        if (first & 0x80) == 0 {
            return (first as usize, 1);
        }

        // Long form: 0x81 = 1 byte follows, 0x82 = 2 bytes follow, etc.
        let num_bytes = (first & 0x7F) as usize;
        if data.len() < 1 + num_bytes {
            return (0, 1);
        }

        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }
        (length, 1 + num_bytes)
    }

    /// Parse a value as a big-endian unsigned integer
    /// Used for simple integer values
    #[allow(dead_code)]
    fn parse_length_value(data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return None;
        }

        // Simple big-endian integer parsing
        let mut value: usize = 0;
        for &byte in data {
            value = (value << 8) | (byte as usize);
        }
        Some(value)
    }
}

/// Key slot types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeySlotType {
    Sig,
    Dec,
    Aut,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::storage::CardDataStore;

    fn create_test_applet() -> OpenPGPApplet {
        let store = CardDataStore::new_temp();
        OpenPGPApplet::new(store)
    }

    #[test]
    fn test_select_openpgp() {
        let mut applet = create_test_applet();
        let cmd = APDU {
            cla: 0x00,
            ins: ins::SELECT,
            p1: 0x04,
            p2: 0x00,
            data: OPENPGP_AID_PREFIX.to_vec(),
            le: None,
        };

        let resp = applet.process_apdu(&cmd);
        assert!(resp.is_okay());
    }

    #[test]
    fn test_get_data_aid() {
        let mut applet = create_test_applet();
        let cmd = APDU {
            cla: 0x00,
            ins: ins::GET_DATA,
            p1: 0x00,
            p2: 0x4F,
            data: Vec::new(),
            le: Some(256),
        };

        let resp = applet.process_apdu(&cmd);
        assert!(resp.is_okay());
        assert!(!resp.data.is_empty());
    }

    #[test]
    fn test_verify_pw1_status() {
        let mut applet = create_test_applet();

        // Check status (empty data)
        let cmd = APDU {
            cla: 0x00,
            ins: ins::VERIFY,
            p1: 0x00,
            p2: 0x81,
            data: Vec::new(),
            le: None,
        };

        let resp = applet.process_apdu(&cmd);
        // Should return counter warning (not yet verified)
        assert!(!resp.is_okay() || resp.sw1 == 0x63);
    }
}
