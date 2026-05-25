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

use ed25519_dalek::{SigningKey, VerifyingKey};
use clap::Parser;
use std::io::Read as StdRead;

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

#[derive(Serialize, Deserialize)]
struct StringTransfer {
    data: String,
    source_pubkey: Vec<u8>,
}

#[derive(Parser)]
#[command(name = "runtime_source")]
struct Cli {
    /// Generate a new Ed25519 key pair: private key at FILE, public key at FILE.pub. Then exit.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["source_private_key", "destination_public_key"])]
    generate_keypair: Option<PathBuf>,

    /// Overwrite existing key files when using --generate-keypair.
    #[arg(long, short = 'f', requires = "generate_keypair")]
    force: bool,

    /// Path to this source's Ed25519 private key file (hex-encoded, 32 bytes).
    /// If the file does not exist, a new key pair is generated and saved here,
    /// with the public key written to <path>.pub automatically.
    #[arg(long, value_name = "FILE", required_unless_present = "generate_keypair")]
    source_private_key: Option<PathBuf>,

    /// Path to the destination's Ed25519 public key file (hex-encoded, 32 bytes).
    #[arg(long, value_name = "FILE", required_unless_present = "generate_keypair")]
    destination_public_key: Option<PathBuf>,
}

/// Load a SigningKey from a hex file, or generate + save a new one if missing.
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

        // Save private key
        std::fs::write(path, hex::encode(key.to_bytes()))
            .with_context(|| format!("Cannot write private key to {:?}", path))?;

        // Save companion public key  (<path>.pub)
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
    info!("|| Runtime Source Starting                      ||");
    info!("==================================================");

    // 1. Load or generate RS's own key pair
    let signing_key = load_or_generate_signing_key(&cli.source_private_key.expect("Mandatory argument, should always be present"))?;
    let source_pubkey = signing_key.verifying_key().to_bytes().to_vec();
    info!("✓ Source public key: {}", hex::encode(&source_pubkey));

    // 2. Load RD's public key
    let dest_vk = load_verifying_key(&cli.destination_public_key.expect("Mandatory argument, should always be present"))?;
    let dest_pubkey = dest_vk.to_bytes().to_vec();
    info!("✓ Destination public key loaded: {}", hex::encode(&dest_pubkey));

    // 3. Read the string from stdin (the part before "| runtime_source ..." in the shell pipe)
    let input_string = {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read from stdin")?;
        // Strip trailing newline added by `echo`
        buf.trim_end_matches('\n').to_string()
    };
    info!("✓ Input string: {:?} ({} bytes)", input_string, input_string.len());

    // 4. Hash the string with BLAKE3 (reuse common::compute_file_hash which is just BLAKE3)
    let string_hash = compute_file_hash(input_string.as_bytes());
    info!("✓ String BLAKE3 hash: {}", string_hash);

        // 5. Connect to RD and TTP
    let stream_d = TcpStream::connect("127.0.0.1:7760")
        .await
        .context("Failed to connect to Runtime Destination")?;
    info!("✓ Connected to destination");

    let stream_ttp = TcpStream::connect("127.0.0.1:9705")
        .await
        .context("Failed to connect to Runtime TTP")?;
    info!("✓ Connected to TTP");

    // 6. Run the fair-exchange protocol
    fair_exchange(
        stream_d,
        stream_ttp,
        input_string,
        string_hash,
        source_pubkey,
        dest_pubkey,
    )
    .await?;

    Ok(())

}

async fn fair_exchange(mut stream_d: TcpStream,
    mut stream_ttp: TcpStream,
    input_string: String,
    string_hash: String,
    source_pubkey: Vec<u8>,
    dest_pubkey: Vec<u8>,) -> Result<()> {
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
        string_metadata: StringMetadata {
            data: input_string.clone(),
            hash: string_hash.clone(),
        },
        source_pubkey: source_pubkey.clone(),
        dest_pubkey: dest_pubkey.clone(),
    };

    let config_bytes = serde_json::to_vec(&init_config)?;

    let _ = agent.call_init(&mut store, &config_bytes).await?; // init() returns void

    info!("AS successfully initialized");

    info!("Step 1 — Sending string to Runtime Destination");
    let transfer = StringTransfer {
        data: input_string.clone(),
        source_pubkey: source_pubkey.clone(),
    };
    let transfer_bytes = serde_json::to_vec(&transfer)?;
    send_bytes(&mut stream_d, &transfer_bytes).await?;
    info!("String sent ({} bytes wire)", transfer_bytes.len());

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
            AgentAction::CompleteSuccess(commitment_json) => {
                info!("=== Protocol Succeeded ===");
                // Print the CommitmentOutput JSON to stdout
                println!("{}", commitment_json);
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
    string_metadata: StringMetadata,
    source_pubkey: Vec<u8>,
    dest_pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum AgentRole {
    Source,
}

#[derive(Serialize, Deserialize)]
struct StringMetadata {
    data: String,
    hash: String,
}
