#[allow(warnings)]
mod bindings;
mod types;
mod identity;
mod agent_source;
mod agent_destination;

use bindings::Guest;
use bindings::fairexchange::unified::types::*;

use types::*;
use agent_source::AgentSource;
use agent_destination::AgentDestination;

use std::cell::RefCell;

thread_local! {
    static AGENT_SOURCE: RefCell<Option<AgentSource>> = RefCell::new(None);
    static AGENT_DESTINATION: RefCell<Option<AgentDestination>> = RefCell::new(None);
}

// Component Implementation
struct Component;

impl Guest for Component {
    // FUNCT 1 - init: func(config: list<u8>)
    fn init(config: Vec<u8>) {
        eprintln!("[Unified-Agent]: Initializing Agent (AS/AD)...");

        // Deserialize config sent by Embedder 
        let config: InitConfig = serde_json::from_slice(&config).expect("Failed to parse initialized config");

        // Based on role of Agent (AS/AD), initialize appropriate configuration
        match config.role {
            AgentRole::Source => {
                let agent_source = AgentSource::new(config.file_metadata, config.source_pubkey, config.dest_pubkey);
                // Store in thread-local state
                AGENT_SOURCE.with(|state| {
                    *state.borrow_mut() = Some(agent_source);
                });
                eprintln!("[Unified-Agent]: AS successfully initialized");
            }
            AgentRole::Destination => {
                let agent_dest = AgentDestination::new(config.file_metadata, config.source_pubkey, config.dest_pubkey);
                AGENT_DESTINATION.with(|state| {
                    *state.borrow_mut() = Some(agent_dest);
                });
                eprintln!("[Unified-Agent]: AD successfully initialized");
            }
        }
    }
    // FUNC 2 - process-message: func(incoming: option<list<u8>>) -> agent-action;
    fn process_message(incoming: Option<Vec<u8>>) -> AgentAction {
        // If AS processes message
        let result = AGENT_SOURCE.with(|state| {
            if let Some(ref mut agent_source) = *state.borrow_mut() {
                Some(agent_source.process(incoming.clone()))
            } else {
                None
            }
        });

        if let Some(action) = result {
            return action;
        }

        // If AD processes message
        let result = AGENT_DESTINATION.with(|state| {
            if let Some(ref mut agent_dest) = *state.borrow_mut() {
                Some(agent_dest.process(incoming.clone()))
            } else {
                None
            }
        });

        if let Some(action) = result {
            return action;
        }

        AgentAction::CompleteFailure("Agent not initialized".to_string())
    }
}

bindings::export!(Component with_types_in bindings);