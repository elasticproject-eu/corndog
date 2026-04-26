use anyhow::{Context, Result};
use common::*;

use tracing::{info, error};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
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
    path: "../agent_ttp/wit",
    world: "ttp-agent",
    async: true,
});

type TtpRequest = (Vec<u8>, oneshot::Sender<Vec<u8>>);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("==================================================");
    info!("||       TTP Runtime Starting                   ||");
    info!("==================================================");
    
    let (tx, rx) = mpsc::channel::<TtpRequest>(32);
    // Spawn a single task that owns a agent_ttp Wasm instance that is being share
    let local = tokio::task::LocalSet::new();
    local.spawn_local(ttp_worker(rx));

    // Listen for connection
    let listener = TcpListener::bind("127.0.0.1:9705").await?;
    println!("Listening on 127.0.0.1:9705");
    
    local.run_until( async move {
        loop {
            let (stream, addr) = listener.accept().await.expect("[RuntimeTtp] Failed to accept a connection");
            println!("✓ Connection from {}", addr);
        
            let tx = tx.clone();
            tokio::task::spawn_local(async move {
                if let Err(e) = dispute_handle(stream, tx).await {
                    error!("Error: {}", e);
                }
            });
        }    
    }).await;
    
    Ok(())
}

// Requestes from different connections are queued through the mpsc channel
async fn ttp_worker(mut rx: mpsc::Receiver<TtpRequest>) {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.async_support(true);
    
    let engine = Engine::new(&config).expect("[RuntimeTTP] Failed to created engine");

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
        "target/wasm32-wasip2/release/agent_ttp.wasm"
    ).expect("[RuntimeTTP] Failed to load component");
    
    info!("TTP Agent Wasm Component loaded");

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_async(&mut linker).expect("[RuntimeTTP] Failed to add WASI to linker");
    
    let agent = TtpAgent::instantiate_async(
        &mut store,
        &component,
        &linker,
    ).await.expect("[RuntimeTTP] Failed to instantiate agent_ttp");

    info!("TTP Agent Wasm Component instantiated");
    
    let _ = agent.call_init(&mut store).await.expect("[RuntimeTTP] Failed to init agent_ttp");

    info!("TTP Agent successfully initialized");

    while let Some((req, resp)) = rx.recv().await {
        match agent.call_process_request(&mut store, &req).await {
            Ok(r) => {
                let _ = resp.send(r);
            }
            Err(e) => {
                error!("TTP Agent error: {}", e);
                let _ = resp.send(b"[TTP] Error happend!".to_vec());
            }
        }
    }
}

async fn dispute_handle(mut stream: TcpStream, tx: mpsc::Sender<TtpRequest>) -> Result<()> {
    loop {
        let recv_bytes = match receive_bytes(&mut stream).await {
            Ok(bytes) => {
                info!("Received {} bytes from a host runtime", bytes.len());
                bytes
            }
            Err(_) => {
                error!("No bytes received from any host runtimes");
                break;
            }
        };
        
        let (resp_tx, resp_rx) = oneshot::channel();
        tx.send((recv_bytes, resp_tx)).await.context("TTP worker channel closed")?;
        let resp = resp_rx.await.context("TTP workder dropped response sender")?;
        send_bytes(&mut stream, &resp).await?;
    }

    Ok(())
}