use blake3;
use hex;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use crate::bindings::fairexchange::unified::types::*;
use crate::types::*;
use crate::identity::*;

const RESOLVE_FLAG: &str = "RESOLVE";

#[derive(Debug)]
enum DestinationState {
    WaitingTrigger,
    WaitingContractAS,
    WaitingSecretAS,
    WaitingResolveTTP,
    Complete,
}

pub struct AgentDestination {
    state: DestinationState,
    source_pubkey: Vec<u8>,
    dest_pubkey: Vec<u8>,
    contract_message: ContractMessage,   // AD's ContractMessage (with commitment_ad)
    secret_ad: [u8; 32],
    data_string: String,
    expected_hash: String,
    commitment_as: Option<Vec<u8>>,
    comm_msg_as: Option<CommunicationMessage>,
    comm_msg_ad: Option<CommunicationMessage>,
    /// Stored here after WaitingSecretAS so Complete can return it.
    commitment_output: Option<String>,
}

impl AgentDestination {
    pub fn new(string_metadata: StringMetadata, source_pubkey: Vec<u8>, dest_pubkey: Vec<u8>) -> Self {
        eprintln!("[AD] Creating Agent");

        // Generate secret_ad
        let mut secret_ad = [0u8; 32];
        for b in &mut secret_ad {
            *b = rand::random::<u8>();
        }

        // Generate commitment_ad
        let commitment_ad = *blake3::hash(&secret_ad).as_bytes();
    
        eprintln!("[AD] Secret and Commitment generated");

        // Compute contract_id before sending
        let mut contract_hasher = Sha256::new();
        contract_hasher.update(string_metadata.hash.as_bytes());
        let contract_id = hex::encode(contract_hasher.finalize());
        
        // Create contract message
        let contract_message = ContractMessage {
            contract_id,
            data_hash: string_metadata.hash.clone(),
            source_pubkey: source_pubkey.clone(),
            dest_pubkey: dest_pubkey.clone(),
            commitment_secret: commitment_ad.to_vec(),
        };

        AgentDestination {
            state: DestinationState::WaitingTrigger,
            source_pubkey,
            dest_pubkey,
            contract_message,
            secret_ad,
            data_string: string_metadata.data.clone(),
            expected_hash: string_metadata.hash.clone(),
            commitment_as: None,
            comm_msg_as: None,
            comm_msg_ad: None,
            commitment_output: None,
        }

    }

    pub fn process(&mut self, incoming: Option<Vec<u8>>) -> AgentAction {
        eprintln!("[AD] State: {:?}", self.state);
        eprintln!("[AD] Incoming message: {}", incoming.is_some());

        match self.state {
            DestinationState::WaitingTrigger => {
                eprintln!("[AD] waiting for first communication message from AS");
                self.state = DestinationState::WaitingContractAS;
                AgentAction::WaitForPeer
            }
            DestinationState::WaitingContractAS => {
                match incoming {
                    Some(bytes) => {
                        eprintln!("[AD] Receiving contract sent by AS");

                        let comm_msg_as: CommunicationMessage = match serde_json::from_slice(&bytes) {
                            Ok(response) => response,
                            Err(_) => {
                                panic!("[AD] Failed to extract communication message sent by AS")
                                // TODO: Need to invoke TTP here
                            }
                        };

                        // Verify signature of AS — reconstruct signed bytes: file_name || file_hash || source_pubkey || dest_pubkey || commitment_secret
                        let c = &comm_msg_as.contract_message;
                        let mut msg_bytes = Vec::new();
                        msg_bytes.extend_from_slice(c.data_hash.as_bytes());
                        msg_bytes.extend_from_slice(&c.source_pubkey);
                        msg_bytes.extend_from_slice(&c.dest_pubkey);
                        msg_bytes.extend_from_slice(&c.commitment_secret);
                        if !Identity::verify(&comm_msg_as.verifying_key_agent, &msg_bytes, &comm_msg_as.contract_signature) {
                            panic!("[AD] Failed to verify signature of AS");
                        }
                         eprintln!("[AD] Successfully verified AS's signature");

                        // Verify that Source's hash matches the hash AD computed from its own stdin
                        if c.data_hash != self.expected_hash {
                            panic!(
                                "[AD] Hash mismatch! Source committed to hash '{}' but Destination computed '{}'",
                                c.data_hash, self.expected_hash
                            );
                        }
                        eprintln!("[AD] Hash verified: Source and Destination agree on the data");

                        self.commitment_as = Some(c.commitment_secret.clone());

                        // Create identity (pk, vk) for AD
                        let identity: Identity = Identity::generate_ephemeral();

                        // Parse contract received from AS
                        let contract_as = comm_msg_as.contract_message.clone();
                        
                        // AD signs contract — same byte layout: file_name || file_hash || source_pubkey || dest_pubkey || commitment_secret
                        let cm = &self.contract_message;
                        let mut msg_for_sign = Vec::new();
                        msg_for_sign.extend_from_slice(cm.data_hash.as_bytes());
                        msg_for_sign.extend_from_slice(&cm.source_pubkey);
                        msg_for_sign.extend_from_slice(&cm.dest_pubkey);
                        msg_for_sign.extend_from_slice(&cm.commitment_secret);

                        let signature_ad = identity.sign(&msg_for_sign).to_vec();
                        let vk_ad_bytes = identity.get_vk_bytes().to_vec();

                        eprintln!("[AD] Sending communication message to AS");
                        let msg = CommunicationMessage {
                            contract_signature: signature_ad,
                            contract_message: self.contract_message.clone(),
                            verifying_key_agent: vk_ad_bytes,
                        };
                        let bytes = serde_json::to_vec(&msg).expect("[AD] Failed to serialize second message to be sent to AS");

                        // Save (comm_msg_as, msg) for later used if need to contact TTP for resolving
                        self.comm_msg_ad = Some(msg);
                        self.comm_msg_as = Some(comm_msg_as);

                        self.state = DestinationState::WaitingSecretAS;
                        AgentAction::SendToPeer(bytes)
                    }
                    None => {
                        eprintln!("[AD] Received no message from AS -> Quit");
                        AgentAction::CompleteFailure("[AD] Fair Exchange does not happen!".to_string())
                    }
                }
            }
            DestinationState::WaitingSecretAS => {
                match incoming {
                    Some(bytes) => {
                        eprintln!("[AD] Received AS's secret");

                        let commitment_as = self.commitment_as.as_ref().unwrap();
                        if blake3::hash(&bytes).as_bytes() != commitment_as.as_slice() {
                            panic!("[AD] AS's secret does not match commitment");
                        }
                        eprintln!("[AD] Verified AS's secret");

                        let output = CommitmentOutput {
                            source_id: hex::encode(&self.source_pubkey),
                            dest_id: hex::encode(&self.dest_pubkey),
                            data: self.data_string.clone(),
                            hash: self.expected_hash.clone(),
                            // commitment_as is inside AS's contract_message
                            signature_source: hex::encode(
                                &self.comm_msg_as.as_ref().unwrap().contract_message.commitment_secret,
                            ),
                            // commitment_ad is inside AD's own contract_message
                            signature_destination: hex::encode(
                                &self.contract_message.commitment_secret,
                            ),
                            status: "commit".to_string(),
                            method: "direct".to_string(),
                        };
                        self.commitment_output = Some(
                            serde_json::to_string_pretty(&output)
                                .expect("[AD] Failed to serialize CommitmentOutput"),
                        );

                        self.state = DestinationState::Complete;
                        eprintln!("[AD] Revealing AD's secret to AS");
                        AgentAction::SendToPeer(self.secret_ad.to_vec())
                    }
                    None => {
                        // Invoke TTP for Resolving
                        let resolve_request = ResolveRequest {
                            request_type: RESOLVE_FLAG.to_string(),
                            comm_msg_as: self.comm_msg_as.as_ref().unwrap().clone(),
                            comm_msg_ad: self.comm_msg_ad.as_ref().unwrap().clone(),
                        };

                        let resolve_request_bytes = serde_json::to_vec(&resolve_request)
                                                                                    .expect("[AD] Failed to serialize resolve request");

                        self.state = DestinationState::WaitingResolveTTP;
                        
                        eprintln!("[AD] Sending Resolve request to TTP");
                        AgentAction::SendToTtp(resolve_request_bytes)
                    }
                }
            }
            DestinationState::WaitingResolveTTP => {
                eprintln!("[AD] Receiving response from TTP");
                match incoming {
                    Some(bytes) => {
                        eprintln!("[AD] Receiving signature signed by TTP");

                        let signed_msg_ttp: TtpResponse = match serde_json::from_slice(&bytes) {
                            Ok(response) => response,
                            Err(_) => {
                                panic!("[AS] failed to extract signature responded by TTP");
                                // No need to do anything
                            }
                        };

                        // Check if response from TTP is "ABORTED" or "RESOLVED"
                        if signed_msg_ttp.response_type.as_str() == "ABORTED" {
                            // Verify signature of TTP on reconstruct message: ABORT || signed_abort_req_as
                            let mut msg_bytes = Vec::new();
                            msg_bytes.extend_from_slice("ABORT".as_bytes());
                            msg_bytes.extend_from_slice(&signed_msg_ttp.signed_abort_req_as.unwrap());

                            if !Identity::verify(&signed_msg_ttp.ttp_verifying_key, &msg_bytes, &signed_msg_ttp.ttp_signature) {
                                panic!("[AS] Failed to verify signature of TTP");
                                // No need to do anything
                            }
                            eprintln!("[AS] Successfully verified AD signature and obtained signed contract with *ABORTED* state");
                        } else {
                            // Response type of TTP is "RESOLVED"
                            // AS reconstruct comm_msg_as || comm_msg_ad
                            let comm_msg_as = self.comm_msg_as.as_ref().expect("[AD] self.comm_msg_as is not set");
                            let comm_msg_ad = self.comm_msg_ad.as_ref().expect("[AD] self.comm_msg_ad is not set");

                            let mut comm_msg_as_ad = Vec::new();
                            comm_msg_as_ad.extend_from_slice(&serde_json::to_vec(&comm_msg_as).unwrap());
                            comm_msg_as_ad.extend_from_slice(&serde_json::to_vec(&comm_msg_ad).unwrap());

                            // Verify signature of TTP on reconstruct message: comm_msg_as || comm_msg_ad
                            let mut msg_bytes = Vec::new();
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_signature);
                            msg_bytes.extend_from_slice(&signed_msg_ttp.ttp_verifying_key);
                            if !Identity::verify(&signed_msg_ttp.ttp_verifying_key, &comm_msg_as_ad, &signed_msg_ttp.ttp_signature) {
                                panic!("[AD] Failed to verify signature of TTP");
                                // No need to do anything
                            }
                            eprintln!("[AD] Successfully verified AD signature and obtained signed contract with *RESOLVED* state");
                        }
                    }
                    None => {
                        eprintln!("[AD] That case would not happen as the TTP must response with data");
                    }
                }
                AgentAction::CompleteSuccess("[AD] Protocol complete (NOT TRUE)".to_string())

            }
            DestinationState::Complete => {
                eprintln!("[AD] Exchange completed");
                let output = self.commitment_output.clone()
                    .unwrap_or_else(|| "[AD] Protocol ended here".to_string());
                AgentAction::CompleteSuccess(output)
            }
        }
    }
}