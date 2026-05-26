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

use ed25519_dalek::{SigningKey, VerifyingKey};
use clap::Parser;
use std::io::Read as StdRead;
use std::net::SocketAddr;

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

#[derive(Parser)]
#[command(name = "runtime_destination")]
struct Cli {
    /// Generate a new Ed25519 key pair: private key at FILE, public key at FILE.pub. Then exit.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["dest_private_key", "source_public_key"])]
    generate_keypair: Option<PathBuf>,

    /// Overwrite existing key files when using --generate-keypair.
    #[arg(long, short = 'f', requires = "generate_keypair")]
    force: bool,

    /// Path to this destination's Ed25519 private key file (hex-encoded, 32 bytes).
    /// If the file does not exist, a new key pair is generated and saved here,
    /// with the public key written to <path>.pub automatically.
    #[arg(long, value_name = "FILE", required_unless_present = "generate_keypair")]
    dest_private_key: Option<PathBuf>,

    /// Path to the source's Ed25519 public key file (hex-encoded, 32 bytes).
    /// Used to independently verify the source identity before trusting the TCP transfer.
    #[arg(long, value_name = "FILE", required_unless_present = "generate_keypair")]
    source_public_key: Option<PathBuf>,

    /// Address to listen on for incoming Source connections.
    #[arg(long, default_value = "0.0.0.0:7760", value_name = "ADDR")]
    listen_addr: SocketAddr,

    /// Address of the TTP runtime to connect to.
    #[arg(long, default_value = "0.0.0.0:9705", value_name = "ADDR")]
    ttp_addr: SocketAddr,
}

fn load_or_generate_signing_key(path: &PathBuf) -> Result<SigningKey> {
    if path.exists() {
        let hex_str = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read private key from {:?}", path))?;
        let bytes = hex::decode(hex_str.trim())
            .context("Private key file is not valid hex")?;
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be exactly 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes_array))
    } else {
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);

        std::fs::write(path, hex::encode(key.to_bytes()))
            .with_context(|| format!("Cannot write private key to {:?}", path))?;

        let pub_path = PathBuf::from(format!("{}.pub", path.display()));
        std::fs::write(&pub_path, hex::encode(key.verifying_key().to_bytes()))
            .with_context(|| format!("Cannot write public key to {:?}", pub_path))?;

        info!("Generated new key pair → {:?}  (pub: {:?})", path, pub_path);
        Ok(key)
    }
}

/// Load a VerifyingKey from a hex file.
fn load_verifying_key(path: &PathBuf) -> Result<VerifyingKey> {
    let hex_str = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read public key from {:?}", path))?;
    let bytes = hex::decode(hex_str.trim())
        .context("Public key file is not valid hex")?;
    let bytes_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes_array).context("Invalid Ed25519 public key")
}

fn generate_keypair_files(path: &PathBuf, force: bool) -> Result<()> {
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    if !force {
        if path.exists() {
            anyhow::bail!("{} already exists; use --force to overwrite", path.display());
        }
        if pub_path.exists() {
            anyhow::bail!("{} already exists; use --force to overwrite", pub_path.display());
        }
    }
    use rand::rngs::OsRng;
    let key = SigningKey::generate(&mut OsRng);
    std::fs::write(path, hex::encode(key.to_bytes()))
        .with_context(|| format!("Cannot write private key to {:?}", path))?;
    std::fs::write(&pub_path, hex::encode(key.verifying_key().to_bytes()))
        .with_context(|| format!("Cannot write public key to {:?}", pub_path))?;
    println!("Generated private key: {}", path.display());
    println!("Generated public key:  {}", pub_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr) // put all output goes to stderr instead of stdout
        .init();

    let cli = Cli::parse();

    if let Some(key_path) = cli.generate_keypair {
        return generate_keypair_files(&key_path, cli.force);
    }

    info!("==================================================");
    info!("|| Runtime Destination Starting                 ||");
    info!("==================================================");

    // Load or generate RD's own key pair
    let signing_key = load_or_generate_signing_key(&cli.dest_private_key.expect("Mandatory argument, should always be present"))?;
    let dest_pubkey = signing_key.verifying_key().to_bytes().to_vec();
    info!("✓ Destination public key: {}", hex::encode(&dest_pubkey));

    // Load Source's long-term public key from file (provided via --source-public-key)
    let source_vk = load_verifying_key(&cli.source_public_key.expect("Mandatory argument, should always be present"))?;
    let expected_source_pubkey = source_vk.to_bytes().to_vec();
    info!("✓ Source public key loaded: {}", hex::encode(&expected_source_pubkey));

    // Read the string from Destination's own stdin (echo "..." | runtime_destination ...)
    let own_string = {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read from stdin")?;
        buf.trim_end_matches('\n').to_string()
    };
    info!("✓ Own input string: {:?} ({} bytes)", own_string, own_string.len());

    // Compute BLAKE3 hash of the string independently
    let own_hash = compute_file_hash(own_string.as_bytes());
    info!("✓ Own BLAKE3 hash: {}", own_hash);

    // Listen for connection from source
    let listener = TcpListener::bind(cli.listen_addr).await?;
    eprintln!("Listening on {}", cli.listen_addr);

    let (stream, addr) = listener.accept().await?;
    eprintln!("✓ Connection from {}", addr);

    let stream_ttp = TcpStream::connect(cli.ttp_addr).await.context("Failed to connect to Runtime TTP")?;
    info!("✓ Connected to TTP");

    // Handle the exchange
    fair_exchange(stream, stream_ttp, dest_pubkey, own_string, own_hash, expected_source_pubkey,).await?;
    
    Ok(())
}

async fn fair_exchange(mut stream: TcpStream, mut stream_ttp: TcpStream, dest_pubkey: Vec<u8>, own_string: String, own_hash: String, expected_source_pubkey: Vec<u8>,) -> Result<()> {
// ── Step 1: Receive the StringTransfer from Source ────────────────────────
    let transfer_bytes = receive_bytes(&mut stream).await
        .context("Failed to receive StringTransfer from RS")?;
    let transfer: StringTransfer = serde_json::from_slice(&transfer_bytes)
        .context("Failed to parse StringTransfer")?;

    let tcp_string = transfer.data;
    let source_pubkey = transfer.source_pubkey;

    info!("✓ Received string via TCP: {:?} ({} bytes)", tcp_string, tcp_string.len());
    info!("✓ Source public key from TCP: {}", hex::encode(&source_pubkey));

    // Verify source_pubkey from TCP matches the key we loaded from --source-public-key
    if source_pubkey != expected_source_pubkey {
        anyhow::bail!(
            "Source public key mismatch! TCP sent: {}, CLI provided: {}",
            hex::encode(&source_pubkey),
            hex::encode(&expected_source_pubkey)
        );
    }
    info!("✓ Source public key verified");

    // Verify the string we received via TCP matches what we read from our own stdin
    if tcp_string != own_string {
        anyhow::bail!(
            "String mismatch! Source sent {:?} but Destination stdin has {:?}",
            tcp_string, own_string
        );
    }
    info!("✓ String match confirmed between TCP and own stdin");

    // Use own independently computed hash — the Agent will compare it against Source's contract
    let input_string = own_string;
    let string_hash = own_hash;

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
        string_metadata: StringMetadata {
            data: input_string.clone(),
            hash: string_hash.clone(),
        },
        source_pubkey: source_pubkey.clone(),
        dest_pubkey: dest_pubkey.clone(),
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
            AgentAction::CompleteSuccess(commitment_json) => {
                info!("=== Protocol Succeeded ===");
                println!("{}", commitment_json);
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
    string_metadata: StringMetadata,
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

#[derive(Serialize, Deserialize)]
struct StringTransfer {
    data: String,
    source_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StringMetadata {
    data: String,
    hash: String,
}