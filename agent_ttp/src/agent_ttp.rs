use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::identity::*;
use crate::types::*;

const ABORT_FLAG: &str = "ABORT";
const RESOLVE_FLAG: &str = "RESOLVE";

#[derive(Deserialize)]
struct RequestType {
    request_type: String, // "ABORT" or "RESOLVE"
}

pub struct AgentTtp {
    identity: Identity,
    sessions: HashMap<Vec<u8>, StatesSession>,
    comm_msg_as: Option<CommunicationMessage>,
    comm_msg_ad: Option<CommunicationMessage>,
    abort_sign_msg_as: Option<Vec<u8>>,  
}

impl AgentTtp {
    pub fn new() -> Self {
        eprintln!("[TTP-Agent]: Initialize a TTP instance");

        // Create identity (vk, sk) for TTP instance
        let identity: Identity = Identity::generate_ephemeral();

        // Initialize an empty sessions for storing (verifying_key_as , states_session)
        let sessions = HashMap::<Vec<u8>, StatesSession>::new();

        AgentTtp {
            identity,
            sessions,
            comm_msg_as: None,
            comm_msg_ad: None,
            abort_sign_msg_as: None,
        }
    }

    pub fn process_request(&mut self, request: Vec<u8>) -> Vec<u8> {
        let req: RequestType = match serde_json::from_slice(&request) {
            Ok(r) => r,
            Err(_) => return b"[TTP-Agent] ERROR - Failed to parse request type".to_vec(),
        };

        match req.request_type.as_str() {
            ABORT_FLAG => {
                let abort_request: AbortRequest = match serde_json::from_slice(&request) {
                    Ok(r) => r,
                    Err(_) => return b"[TTP-Agent] Invalid Abort Request".to_vec(),
                };
                self.handle_abort_request(&abort_request)
            }
            RESOLVE_FLAG => {
                let resolve_request: ResolveRequest = match serde_json::from_slice(&request) {
                    Ok(r) => r,
                    Err(_) => return b"[TTP-Agent] Invalid Resolve Request".to_vec(),
                };
                self.handle_resolve_request(&resolve_request)
            }
            _ => b"[TTP-Agent] Invalid Request. Not in a format of ABORT or RESOLVE".to_vec(),
        }
    }

    pub fn handle_abort_request(&mut self, abort_request: &AbortRequest) -> Vec<u8> {
        if !self.verify_signed_abort_request(abort_request) {
            // Do nothing as the AS is forged then no need to response
            return b"[TTP-Agent] Invalid AS signature for Abort".to_vec()
        }

        let verifying_key_as = abort_request.comm_msg_as.verifying_key_agent.clone();

        // Retrieving existing session corresponding to this verifying_key_as or creating a new session for this key
        let session = self.sessions.entry(verifying_key_as).or_insert_with(|| StatesSession {
            aborted: false,
            resolved: false,
            aborted_sign_ttp: None,
            resolved_sign_ttp: None,
            signed_abort_req_as: None,
        });

        if session.resolved {
            eprintln!("[TTP-Agent] The system has already been RESOLVED");
            
            let abort_response_ttp = TtpResponse {
                response_type: "RESOLVED".to_string(),
                ttp_signature: session.resolved_sign_ttp.clone().unwrap_or_else(|| b"[TTP-Agent]: Resolve Signature is not set in Abort request".to_vec()),
                ttp_verifying_key: self.identity.get_vk_bytes().to_vec(),
                signed_abort_req_as: None,
            };
            serde_json::to_vec(&abort_response_ttp).expect("[TTP-Agent] Failed to serialized response from TTP before sending to AS")

        } else {
            session.aborted = true;
            let abort_request_byte = serde_json::to_vec(abort_request).expect("[TTP-Agent] Failed to convert abort_request to vector");
            // TTP signs on (ABORTED_FLAG, abort_request)
            let mut msg = Vec::new();
            msg.extend_from_slice(ABORT_FLAG.as_bytes());
            msg.extend_from_slice(&abort_request_byte);

            let signed_msg = self.identity.sign(&msg).to_vec();

            // Save response signed by TTP and signed abort request from AS in this current session
            session.aborted_sign_ttp = Some(signed_msg.clone());
            session.signed_abort_req_as = Some(abort_request_byte.clone());

            eprintln!("[TTP-Agent] Confirm to ABORT the migration");

            let abort_response_ttp = TtpResponse {
                response_type: "ABORTED".to_string(),
                ttp_signature: signed_msg,
                ttp_verifying_key: self.identity.get_vk_bytes().to_vec(),
                signed_abort_req_as: Some(abort_request_byte),
            };

            eprintln!("[TTP-Agent] Sending signed ABORTED contract to AS");
            serde_json::to_vec(&abort_response_ttp).expect("[TTP-Agent] Failed to serialized response from TTP before sending to AS")
        } 
    }

    pub fn handle_resolve_request(&mut self, resolve_request: &ResolveRequest) -> Vec<u8> {
        if !self.verify_signed_resolve_request(resolve_request) {
            // Do nothing as AD or AS is forged then no need to response
            return b"[TTP-Agent] Invalid AS or/and AD signature(s) for Resolve".to_vec()
        }

        let verifying_key_as = resolve_request.comm_msg_as.verifying_key_agent.clone();

        // Retrieving existing session corresponding to this verifying_key_as or creating a new session for this key
        let session = self.sessions.entry(verifying_key_as).or_insert_with(|| StatesSession {
            aborted: false,
            resolved: false,
            aborted_sign_ttp: None,
            resolved_sign_ttp: None,
            signed_abort_req_as: None,
        });

        if session.aborted {
            eprintln!("[TTP-Agent] The system has already been ABORTED");
            
            let resolve_response_ttp = TtpResponse {
                response_type: "ABORTED".to_string(),
                ttp_signature: session.aborted_sign_ttp.clone().unwrap_or_else(|| b"[TTP-Agent]: Abort Signature is not set in this session".to_vec()),
                ttp_verifying_key: self.identity.get_vk_bytes().to_vec(),
                signed_abort_req_as: Some(session.signed_abort_req_as.clone().unwrap_or_else(|| b"[TTP-Agent] signed abort request of AS is None".to_vec())),
            };
            serde_json::to_vec(&resolve_response_ttp).expect("[TTP-Agent] Failed to serialized Resolve response from TTP before sending to AS")
        } else {
            session.resolved = true;
            // TTP signs on (comm_msg_as, comm_msg_ad)
            let mut msg = Vec::new();
            msg.extend_from_slice(&serde_json::to_vec(&resolve_request.comm_msg_as)
                                        .expect("[TTP-Agent] Failed to serialize comm_msg_as"));
            msg.extend_from_slice(&serde_json::to_vec(&resolve_request.comm_msg_ad)
                                        .expect("[TTP-Agent] Failed to serialize comm_msg_ad"));

            let signed_msg = self.identity.sign(&msg).to_vec();

            // Save response signed by TTP in this current session
            session.resolved_sign_ttp = Some(signed_msg.clone());

            eprintln!("[TTP-Agent] Confirm to RESOLVE the migration");

            let resolve_response_ttp = TtpResponse {
                response_type: "RESOLVED".to_string(),
                ttp_signature: signed_msg,
                ttp_verifying_key: self.identity.get_vk_bytes().to_vec(),
                signed_abort_req_as: None,
            };

            eprintln!("[TTP-Agent] Sending signed RESOLVED contract to requested Agent");
            serde_json::to_vec(&resolve_response_ttp).expect("[TTP-Agent] Failed to serialized Resolve response from TTP before sending to AS")
        }
    }

    pub fn verify_signed_abort_request(&self, abort_req: &AbortRequest) -> bool {
        let abort_sig = &abort_req.abort_sig;
        let comm_msg_as = &abort_req.comm_msg_as;

        let mut abort_request_bytes = Vec::new();
        abort_request_bytes.extend_from_slice(ABORT_FLAG.as_bytes());
        abort_request_bytes.extend_from_slice(&serde_json::to_vec(comm_msg_as).expect("[TTP-Agent] Failed to extract comm_msg_as sent by AS"));

        let verifying_key_as = &comm_msg_as.verifying_key_agent;
        
        if !Identity::verify(&verifying_key_as, &abort_request_bytes, &abort_sig) {
            eprintln!("[TTP-Agent] Failed to verify signature of AS in the first communication message");
            return false
        }
        eprintln!("[TTP-Agent] Successfully verified AS signature");
        return true
    }

    pub fn verify_signed_resolve_request(&self, resolve_req: &ResolveRequest) -> bool {
        let comm_msg_as = &resolve_req.comm_msg_as;
        let comm_msg_ad = &resolve_req.comm_msg_ad;

        let cm_ad = &comm_msg_ad.contract_message;
        let mut cm_ad_bytes = Vec::new();
        cm_ad_bytes.extend_from_slice(cm_ad.file_name.as_bytes());
        cm_ad_bytes.extend_from_slice(cm_ad.file_hash.as_bytes());
        cm_ad_bytes.extend_from_slice(&cm_ad.source_pubkey);
        cm_ad_bytes.extend_from_slice(&cm_ad.dest_pubkey);
        cm_ad_bytes.extend_from_slice(&cm_ad.commitment_secret);
        if !Identity::verify(&comm_msg_ad.verifying_key_agent, &cm_ad_bytes, &comm_msg_ad.contract_signature) {
            eprintln!("[TTP-Agent] Failed to verify signature of AD");
            return false
        }

        let cm_as = &comm_msg_as.contract_message;
        let mut cm_as_bytes = Vec::new();
        cm_as_bytes.extend_from_slice(cm_as.file_name.as_bytes());
        cm_as_bytes.extend_from_slice(cm_as.file_hash.as_bytes());
        cm_as_bytes.extend_from_slice(&cm_as.source_pubkey);
        cm_as_bytes.extend_from_slice(&cm_as.dest_pubkey);
        cm_as_bytes.extend_from_slice(&cm_as.commitment_secret);
        if !Identity::verify(&comm_msg_as.verifying_key_agent, &cm_as_bytes, &comm_msg_as.contract_signature) {
            eprintln!("[TTP-Agent] Failed to verify signature of AS");
            return false
        }

        eprintln!("[TTP-Agent] Successfully verify signatures of AS and AD");
        return true
    }
}