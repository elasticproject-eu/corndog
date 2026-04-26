const TIMEOUT: Duration = Duration::from_secs(5);
const DELAY_SECRET_AS: Duration = Duration::from_secs(10);

use anyhow::{Context, Result};
use common::*;

use tracing::{info, error};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

use wasmtime::component::*;
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

struct HostState {
    wasi_ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx { &mut self.wasi_ctx }
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
}

wasmtime::component::bindgen!({
    path: "../agent_source_destination/wit",
    world: "unified-agent",
    async: true,
});

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("==================================================");
    info!("|| Runtime Source Starting                      ||");
    info!("==================================================");

    // Read generic data
    let file_path = PathBuf::from("test-files/data.txt");
    let file_data = std::fs::read(&file_path)
        .context("Failed to read test file")?;
    let file_hash = compute_file_hash(&file_data);
    let file_name = file_path.file_name().unwrap().to_str().unwrap().to_string();
    
    info!("✓ File: {} ({} bytes)", file_name, file_data.len());
    info!("✓ File hash: {}", &file_hash);

    let stream_d = TcpStream::connect("127.0.0.1:7760").await.context("Failed to connect to Runtime Destination")?;
    info!("✓ Connected to destination");

    let stream_ttp = TcpStream::connect("127.0.0.1:9705").await.context("Failed to connect to Runtime TTP")?;
    info!("✓ Connected to TTP");

    fair_exchange(stream_d, stream_ttp, file_name.clone(), file_hash, file_data).await?;

    Ok(())

}

async fn fair_exchange(mut stream_d: TcpStream, mut stream_ttp: TcpStream, file_name: String, file_hash: String, file_data: Vec<u8>) -> Result<()> {
    // Load component
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);

    let engine = Engine::new(&config)?;

    let wasi_ctx = WasiCtxBuilder::new()
        .inherit_stderr()
        .inherit_stdout()
        .build();

    let mut store = Store::new(&engine, HostState {
        wasi_ctx,
        table: ResourceTable::new(),
    });

    let component = Component::from_file(&engine, "target/wasm32-wasip2/release/agent_source_destination.wasm")?;

    info!("Wasm Component loaded");

    // Instantiate component
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_async(&mut linker)?;

    let agent = UnifiedAgent::instantiate_async(&mut store, &component, &linker).await?;

    info!("Wasm Component instantiated");

    // Initialize agent with config
    let init_config = InitConfig {
        role: AgentRole::Source,
        file_metadata: FileMetaData {
            file_name: file_name.clone(),
            file_hash: file_hash.clone(),
        },
        source_pubkey: vec![1u8; 32], // TODO: Need to update with real public key
        dest_pubkey: vec![1u8; 32], // TODO: Need to update with real public key
    };

    let config_bytes = serde_json::to_vec(&init_config)?;

    let _ = agent.call_init(&mut store, &config_bytes).await?; // init() returns void

    info!("AS successfully initialized");

    info!("Step 1 - File sending");
    send_file(&mut stream_d, &file_name, &file_data).await?;
    info!("Complete file sending");

    let mut counter = 0; // Set a counter to add delay when AS sends secret_as

    // Start communication between AS and AD
    let mut action = agent.call_process_message(&mut store, None).await?;
    loop {
        // Handle `action` (type AgentAction)
        match action {
            AgentAction::SendToPeer(bytes) => {
                info!("Send {} bytes to RuntimeD", bytes.len());
                counter += 1;
                if counter == 2 {
                    // ===== TEST CASE OF SLEEPING =====
                    // info!("Delay sending Secret_AS for {:#?} seconds", DELAY_SECRET_AS);
                    // tokio::time::sleep(DELAY_SECRET_AS).await;
                    // info!("Finish delaying. Now sending bytes to RuntimeS");
                    // =====   TEST CASE FINISHES  =====
                }
                send_bytes(&mut stream_d, &bytes).await?;

                match timeout(TIMEOUT, receive_bytes(&mut stream_d)).await {
                    Ok(Ok(recv)) => {
                        action = agent.call_process_message(&mut store, Some(&recv)).await?;
                    }
                    Ok(Err(_)) | Err(_) => {
                        error!("Connection error waiting for AD");
                        action = agent.call_process_message(&mut store, None).await?;
                    }
                }
            }
            AgentAction::SendToTtp(bytes) => {
                info!("Send {} bytes to RuntimeTTP", bytes.len());
                send_bytes(&mut stream_ttp, &bytes).await?;
                let ttp_response = receive_bytes(&mut stream_ttp).await?;
                info!("Receive {} bytes from RuntimeTTP", ttp_response.len());
                action = agent.call_process_message(&mut store, Some(&ttp_response)).await?;
            }
            AgentAction::CompleteSuccess(reason) => {
                info!("Exchange completed with: {}", reason);
                break;
            }
            AgentAction::CompleteFailure(reason) => {
                info!("Exchange failed with reason: {}", reason);
                return Err(anyhow::anyhow!(reason));
            }
            AgentAction::WaitForPeer => {
                let recv = receive_bytes(&mut stream_d).await?;
                action = agent.call_process_message(&mut store, Some(&recv)).await?;
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct InitConfig {
    role: AgentRole,
    file_metadata: FileMetaData,
    source_pubkey: Vec<u8>,
    dest_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum AgentRole {
    Source,
}

#[derive(Serialize, Deserialize)]
struct FileMetaData {
    file_name: String,
    file_hash: String,
}