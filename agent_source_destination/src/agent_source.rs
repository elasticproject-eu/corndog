use blake3;
use hex;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use crate::bindings::fairexchange::unified::types::*;
use crate::types::*;
use crate::identity::*;

const ABORT_FLAG: &str = "ABORT";
const RESOLVE_FLAG: &str = "RESOLVE";

#[derive(Serialize, Deserialize, Debug)]
enum SourceState {
    WaitingTrigger,
    WaitingVerificationAD,
    WaitingSecretAD,
    WaitingAbortTTP,
    WaitingResolveTTP,
    //WaitingTtp,
    Complete,
}

pub struct AgentSource {
    state: SourceState,
    identity: Identity, // Need this to sign ABORT message
    verifying_key_as: [u8; 32],
    contract_message: ContractMessage,
    contract_signature: Vec<u8>,
    secret_as: [u8; 32],
    data_string: String,
    commitment_ad: Option<Vec<u8>>,
    comm_msg_as: Option<CommunicationMessage>, // Send this to TTP for ABORTING
    comm_msg_ad: Option<CommunicationMessage>, // Send this with comm_msg_as to TTP for RESOLVING
}

impl AgentSource {
    pub fn new(string_metadata: StringMetadata, source_pubkey: Vec<u8>, dest_pubkey: Vec<u8>) -> Self {
        eprintln!("[AS] Creating Agent");

        // Create identity (vk, sk) for AS
        let identity: Identity = Identity::generate_ephemeral();

        // Generate secret_as
        let mut secret_as = [0u8; 32];
        for b in &mut secret_as {
            *b = rand::random::<u8>();
        }

        // Generate commitment_as
        let commitment_as = *blake3::hash(&secret_as).as_bytes();
    
        eprintln!("[AS] Secret and Commitment generated");

        // Compute contract_id before sending
        let mut contract_hasher = Sha256::new();
        contract_hasher.update(string_metadata.hash.as_bytes());
        let contract_id = hex::encode(contract_hasher.finalize());

        // AS signs contract
        let mut contract_msg = Vec::new();
        contract_msg.extend_from_slice(string_metadata.hash.as_bytes());
        contract_msg.extend_from_slice(&source_pubkey);
        contract_msg.extend_from_slice(&dest_pubkey);
        contract_msg.extend_from_slice(&commitment_as);

        // sigma_{S}
        let contract_signature = identity.sign(&contract_msg).to_vec(); 

        // Get verifying key of AS
        let vk_as_bytes = identity.get_vk_bytes();

        // Create contract message
        let contract_message = ContractMessage {
            contract_id,
            data_hash: string_metadata.hash.clone(),
            source_pubkey: source_pubkey.clone(),
            dest_pubkey: dest_pubkey.clone(),
            commitment_secret: commitment_as.to_vec(),
        };

        AgentSource {
            state: SourceState::WaitingTrigger,
            identity,
            verifying_key_as: vk_as_bytes,
            contract_message,
            contract_signature,
            secret_as,
            data_string: string_metadata.data.clone(),
            commitment_ad: None,
            comm_msg_as: None,
            comm_msg_ad: None,
        }

    }

    pub fn process(&mut self, incoming: Option<Vec<u8>>) -> AgentAction {
        eprintln!("[AS] State: {:?}", self.state);
        if !incoming.is_some() {
            eprintln!("[AS] Incoming message is empty");
        } else {
            eprintln!("[AS] Incoming message is not empty",);
        }
        
        match self.state {
            SourceState::WaitingTrigger => {
                eprintln!("[AS] Sending signing contract to AD");

                let msg = CommunicationMessage {
                    contract_signature: self.contract_signature.clone(),
                    contract_message: self.contract_message.clone(),
                    verifying_key_agent: self.verifying_key_as.to_vec(),
                };
                let bytes = serde_json::to_vec(&msg).expect("[AS] Failed to serialized first message to be sent to AD");
                self.comm_msg_as = Some(msg);
                self.state = SourceState::WaitingVerificationAD;
                AgentAction::SendToPeer(bytes)
            }
            SourceState::WaitingVerificationAD => {
                match incoming {
                    Some(bytes) => {
                        eprintln!("[AS] Receiving Verification sent by AD");

                        let comm_msg: CommunicationMessage = match serde_json::from_slice(&bytes) {
                            Ok(response) => response,
                            Err(_) => {
                                panic!("[AS] failed to extract communication message sent by AD");
                                //TODO: Need to invoke TTP for aborting here
                            }
                        };
                        
                        // Verify signature of AD — reconstruct signed bytes: file_name || file_hash || source_pubkey || dest_pubkey || commitment_secret
                        let c = &comm_msg.contract_message;
                        let mut msg_bytes = Vec::new();
                        msg_bytes.extend_from_slice(c.data_hash.as_bytes());
                        msg_bytes.extend_from_slice(&c.source_pubkey);
                        msg_bytes.extend_from_slice(&c.dest_pubkey);
                        msg_bytes.extend_from_slice(&c.commitment_secret);
                        if !Identity::verify(&comm_msg.verifying_key_agent, &msg_bytes, &comm_msg.contract_signature) {
                            panic!("[AS] Failed to verify signature of AD");
                            // TODO: Need to invoke TTP for aborting here
                        }
                        eprintln!("[AS] Successfully verified AD signature");

                        // Save commitment_ad for later verifying with AD's secret
                        self.commitment_ad = Some(comm_msg.contract_message.commitment_secret.clone());

                        // Save comm_msg for later used if need to contact TTP for resolving
                        self.comm_msg_ad = Some(comm_msg);

                        eprintln!("[AS] Revealing AS's secret");
                        self.state = SourceState::WaitingSecretAD;

                        AgentAction::SendToPeer(self.secret_as.to_vec())
                        
                    }
                    None => {
                        // TODO: Handle multiple ABORT requests to multiple TTPs
                        eprintln!("[AS] Timeout - Invoking TTP abort");

                        let comm_msg_as = self.comm_msg_as.as_ref().expect("[AS] self.comm_msg_as is not set");
                        
                        let mut abort_request_bytes = Vec::new();
                        abort_request_bytes.extend_from_slice(ABORT_FLAG.as_bytes());
                        abort_request_bytes.extend_from_slice(&serde_json::to_vec(comm_msg_as).expect("[AS] Failed to serialize self.comm_msg_as"));

                        let abort_sig = self.identity.sign(&abort_request_bytes).to_vec();

                        let abort_request = AbortRequest {
                            request_type: ABORT_FLAG.to_string(),
                            abort_sig,
                            comm_msg_as: comm_msg_as.clone()
                         };

                        self.state = SourceState::WaitingAbortTTP;

                        eprintln!("[AS] Sending Abort message to TTP");

                        let abort_request_bytes = serde_json::to_vec(&abort_request).expect("[AS] Failed to serialize abort request");                        
                        AgentAction::SendToTtp(abort_request_bytes)
                    }
                }
            }
            SourceState::WaitingSecretAD => {
                match incoming {
                    Some (bytes) => {
                        eprintln!("[AS] Received AD's secret");

                        let commitment_ad = self.commitment_ad.as_ref().unwrap();
                        if blake3::hash(&bytes).as_bytes() != commitment_ad.as_slice() {
                            panic!("[AS] AD's secret does not match commitment");
                        }
                        eprintln!("[AS] Verified AD's secret — protocol complete");

                        let output = CommitmentOutput {
                            source_id: hex::encode(&self.contract_message.source_pubkey),
                            dest_id: hex::encode(&self.contract_message.dest_pubkey),
                            data: self.data_string.clone(),
                            hash: self.contract_message.data_hash.clone(),
                            // commitment_as = BLAKE3(secret_as), stored inside AS's contract
                            signature_source: hex::encode(&self.contract_message.commitment_secret),
                            // commitment_ad = BLAKE3(secret_ad), stored inside AD's contract
                            signature_destination: hex::encode(
                                &self.comm_msg_ad.as_ref().unwrap().contract_message.commitment_secret,
                            ),
                            status: "commit".to_string(),
                            method: "direct".to_string(),
                        };
                        
                        let output_json = serde_json::to_string_pretty(&output)
                            .expect("[AS] Failed to serialize CommitmentOutput");

                        AgentAction::CompleteSuccess(output_json)
                    }
                    None => {
                        // Invoke TTP for Resolving
                        self.state = SourceState::WaitingResolveTTP;

                        let resolve_request = ResolveRequest {
                            request_type: RESOLVE_FLAG.to_string(),
                            comm_msg_as: self.comm_msg_as.as_ref().unwrap().clone(),
                            comm_msg_ad: self.comm_msg_ad.as_ref().unwrap().clone(),
                        };

                        let resolve_request_bytes = serde_json::to_vec(&resolve_request)
                                                                                    .expect("[AS] Failed to serialize resolve request");
                        
                        eprintln!("[AS] Sending Resolve request to TTP");
                        AgentAction::SendToTtp(resolve_request_bytes)
                    }
                }
            }
            SourceState::WaitingAbortTTP | SourceState::WaitingResolveTTP => {
                eprintln!("[AS] Receiving response from TTP");
                match incoming {
                    Some(bytes) => {
                        eprintln!("[AS] Receiving signature signed by TTP on Abort request");

                        let signed_msg_ttp: TtpResponse = match serde_json::from_slice(&bytes) {
                            Ok(response) => response,
                            Err(_) => {
                                panic!("[AS] failed to extract signature responded by TTP");
                                // No need to do anything
                            }
                        };

                        // Check if response from TTP is "ABORTED" or "RESOLVED"
                        if signed_msg_ttp.response_type.as_str() == "ABORTED" {
                            // Re-construct the signed abort request by AS itself 
                            // Similar to the source code inside None arm of SourceState::WaitingVerificationAD above
                            let comm_msg_as = self.comm_msg_as.as_ref().expect("[AS] self.comm_msg_as is not set");
                            
                            let mut abort_request_bytes = Vec::new();
                            abort_request_bytes.extend_from_slice(ABORT_FLAG.as_bytes());
                            abort_request_bytes.extend_from_slice(&serde_json::to_vec(comm_msg_as).expect("[AS] Failed to serialize self.comm_msg_as"));

                            let abort_sig = self.identity.sign(&abort_request_bytes).to_vec();

                            let abort_request = AbortRequest {
                                request_type: ABORT_FLAG.to_string(),
                                abort_sig,
                                comm_msg_as: comm_msg_as.clone()
                            };

                            let mut signed_abort_request_bytes = Vec::new();
                            signed_abort_request_bytes.extend_from_slice(ABORT_FLAG.as_bytes());
                            signed_abort_request_bytes.extend_from_slice(&serde_json::to_vec(&abort_request).expect("[AS] Failed to convert abort_request to vector"));
                            
                            // Verify signature of TTP — reconstruct signed bytes: ABORT_FLAG || signed abort message sent by AS
                            let mut msg_bytes = Vec::new();
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_signature);
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_verifying_key);
                            if !Identity::verify(&signed_msg_ttp.ttp_verifying_key, &signed_abort_request_bytes, &signed_msg_ttp.ttp_signature) {
                                panic!("[AS] Failed to verify signature of TTP");
                                // No need to do anything
                            }
                            eprintln!("[AS] Successfully verified AD signature and obtained signed contract with *ABORTED* state");
                        } else {
                            // Response type of TTP is "RESOLVED"
                            // AS reconstruct comm_msg_as || comm_msg_ad
                            let comm_msg_as = self.comm_msg_as.as_ref().expect("[AS] self.comm_msg_as is not set");
                            let comm_msg_ad = self.comm_msg_ad.as_ref().expect("[AS] self.comm_msg_ad is not set");

                            let mut comm_msg_as_ad = Vec::new();
                            comm_msg_as_ad.extend_from_slice(&serde_json::to_vec(&comm_msg_as).unwrap());
                            comm_msg_as_ad.extend_from_slice(&serde_json::to_vec(&comm_msg_ad).unwrap());

                            // Verify signature of TTP on reconstruct message: comm_msg_as || comm_msg_ad
                            let mut msg_bytes = Vec::new();
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_signature);
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_verifying_key);
                            if !Identity::verify(&signed_msg_ttp.ttp_verifying_key, &comm_msg_as_ad, &signed_msg_ttp.ttp_signature) {
                                panic!("[AS] Failed to verify signature of TTP");
                                // No need to do anything
                            }
                            eprintln!("[AS] Successfully verified AD signature and obtained signed contract with *RESOLVED* state");
                        }
                    }
                    None => {
                        eprintln!("[AS] That case would not happen as the TTP must response with data");
                    }
                }
                AgentAction::CompleteSuccess("[AS] Protocol completed".to_string())
            }
            SourceState::Complete => {
                eprintln!("[AS] Exchange completed");
                AgentAction::CompleteSuccess("[AS] Protocol ended here".to_string())
            }
        }
    }
}