const DELAY_MSG_AD: Duration = Duration::from_secs(10);
const DELAY_SECRET_AD: Duration = Duration::from_secs(10);
const TIMEOUT: Duration = Duration::from_secs(5);


use anyhow::{Context, Result};
use common::*;

use tracing::{info, error};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

use tokio::net::{TcpStream, TcpListener};
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
    info!("|| Runtime Destination Starting                 ||");
    info!("==================================================");
    
    // Listen for connection from source
    let listener = TcpListener::bind("127.0.0.1:7760").await?;
    println!("Listening on 127.0.0.1:7760");
    
    let (stream, addr) = listener.accept().await?;
    println!("✓ Connection from {}", addr);

    let stream_ttp = TcpStream::connect("127.0.0.1:9705").await.context("Failed to connect to Runtime TTP")?;
    info!("✓ Connected to TTP");

    // Handle the exchange
    fair_exchange(stream, stream_ttp).await?;
    
    Ok(())
}

async fn fair_exchange(mut stream: TcpStream, mut stream_ttp: TcpStream) -> Result<()> {
    let (file_name, file_data) = receive_file(&mut stream).await?;
    let file_hash = compute_file_hash(&file_data);
    
    info!("✓ File received: {} ({} bytes)", file_name, file_data.len());
    info!("✓ File hash: {}", &file_hash);

    // Load Wasm Component
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

    let component = Component::from_file(
        &engine,
        "target/wasm32-wasip2/release/agent_source_destination.wasm"
    )?;
    
    info!("Wasm Component loaded");

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_async(&mut linker)?;
    
    let agent = UnifiedAgent::instantiate_async(
        &mut store,
        &component,
        &linker,
    ).await?;

    info!("Wasm Component instantiated");

    let init_config = InitConfig {
        role: AgentRole::Destination,
        file_metadata: FileMetaData {
            file_name: file_name.clone(),
            file_hash: file_hash.clone(),
        },
        source_pubkey: vec![1u8; 32],
        dest_pubkey: vec![2u8; 32],
    };
    
    let config_bytes = serde_json::to_vec(&init_config)?;
    
    let _ = agent.call_init(&mut store, &config_bytes).await?;

    info!("AD successfully initialized");

    let mut counter = 0; // Set a counter to add delay when AD sends verification_ad or secret_ad
    let mut action = agent.call_process_message(&mut store, None).await?;
    loop {
        match action {
            AgentAction::SendToPeer(bytes) => {
                info!("Send {} bytes to AS", bytes.len());
                counter += 1;
                if counter == 1 {
                    // ===== TEST CASE OF SLEEPING =====
                    // info!("Delay sending VerificationAD for {:#?} seconds", DELAY_MSG_AD);
                    // tokio::time::sleep(DELAY_MSG_AD).await;
                    // info!("Finish delaying. Now sending VerficationAD (bytes) to RuntimeS");
                    // =====   TEST CASE FINISHES  =====
                } if counter == 2 {
                    // ===== TEST CASE OF SLEEPING =====
                    // info!("Delay sending Secret_AD for {:#?} seconds", DELAY_SECRET_AD);
                    // tokio::time::sleep(DELAY_SECRET_AD).await;
                    // info!("Finish delaying. Now sending Secret_AD (bytes) to RuntimeS");
                    // =====   TEST CASE FINISHES  =====
                }
                send_bytes(&mut stream, &bytes).await?;
                
                match timeout(TIMEOUT, receive_bytes(&mut stream)).await {
                    Ok(Ok(recv)) => {
                        action = agent.call_process_message(&mut store, Some(&recv)).await?;
                    }
                    Ok(Err(_)) | Err(_) => {
                        // AS closed the connection after receiving the last message — we're done
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
                let recv = receive_bytes(&mut stream).await?;
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
    Destination,
}

#[derive(Serialize, Deserialize)]
struct FileMetaData {
    file_name: String,
    file_hash: String,
}