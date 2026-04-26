use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct InitConfig {
    pub role: AgentRole,
    pub file_metadata: FileMetadata,
    pub source_pubkey: Vec<u8>,
    pub dest_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum AgentRole {
    Source,
    Destination,
}

#[derive(Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_name: String,
    pub file_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct AbortRequest {
    pub request_type: String,
    pub abort_sig: Vec<u8>,
    pub comm_msg_as: CommunicationMessage,
}

#[derive(Serialize, Deserialize)]
pub struct ResolveRequest {
    pub request_type: String,
    pub comm_msg_as: CommunicationMessage,
    pub comm_msg_ad: CommunicationMessage,
}

#[derive(Serialize, Deserialize)]
pub struct TtpResponse {
    pub response_type: String, // "ABORTED or "RESOLVED"
    pub ttp_signature: Vec<u8>, 
    pub ttp_verifying_key: Vec<u8>,
    pub signed_abort_req_as: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub enum Decision {
    Abort {sig_as: Vec<u8>, sig_aborted: Vec<u8>},
    Resolve {sig_as: Vec<u8>, sig_ad: Vec<u8>},
}

// Protocol message types (passed between AS <-> AD)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContractMessage {
    pub contract_id: String,
    pub file_name: String,
    pub file_hash: String,
    pub source_pubkey: Vec<u8>,
    pub dest_pubkey: Vec<u8>,
    pub commitment_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommunicationMessage {
    pub contract_signature: Vec<u8>,
    pub contract_message: ContractMessage,
    pub verifying_key_agent: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretMessage {
    pub secret: Vec<u8>,
}
