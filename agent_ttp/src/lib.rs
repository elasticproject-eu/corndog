#[allow(warnings)]
mod bindings;
mod identity;
mod types;
mod agent_ttp;

use bindings::Guest;
use agent_ttp::AgentTtp;

use std::cell::RefCell;

thread_local! {
    static AGENT_TTP: RefCell<Option<AgentTtp>> = RefCell::new(None); 
}

struct Component;

impl Guest for Component {
    fn init() {
        eprintln!("[TTP-AgentLib]: Initializing TTP Agent...");
        AGENT_TTP.with(|state| {
            *state.borrow_mut() = Some(AgentTtp::new());
        });
        eprintln!("[TTP-AgentLib]: Finished Initializing TTP Agent");
    }

    fn process_request(incoming_request:Vec<u8>) -> Vec<u8> {
        AGENT_TTP.with(|state| {
            match state.borrow_mut().as_mut() {
                Some(agent) => agent.process_request(incoming_request),
                None => b"[TTP-AgentLib] Error - TTP not initialized".to_vec(),
            }
        })
    }
}

bindings::export!(Component with_types_in bindings);