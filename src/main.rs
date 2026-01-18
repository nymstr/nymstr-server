mod crypto_utils;
mod db_utils;
mod env_loader;
mod log_config;
mod message_utils;

use crate::crypto_utils::CryptoUtils;
use crate::db_utils::DbUtils;
use crate::env_loader::load_env;
use crate::log_config::init_logging;
use crate::message_utils::MessageUtils;
use nym_sdk::mixnet::{MixnetClientBuilder, StoragePaths};
use std::path::PathBuf;
use std::process::Command;
use std::io::{self, Write};
use tokio_stream::StreamExt;
use bip39::{Mnemonic, Language};

/// Generate a new BIP39 seed phrase and store it
fn generate_and_store_seed_phrase(secret_path: &PathBuf) -> anyhow::Result<String> {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  ⚠️  IMPORTANT: BACK UP YOUR SEED PHRASE NOW!");
    println!("═══════════════════════════════════════════════════════════════");

    // Generate 24-word mnemonic (256 bits of entropy)
    let mnemonic = Mnemonic::generate_in(Language::English, 24)?;
    let phrase = mnemonic.to_string();

    println!("\n{}\n", phrase);
    println!("This seed phrase protects all encrypted keys in this server.");
    println!("Write it down and store it securely. You'll need it to recover");
    println!("your keys if this file is lost or deleted.\n");

    println!("Do you want to encrypt this seed phrase with a password? (y/N): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().eq_ignore_ascii_case("y") {
        println!("\n⚠️  You chose encryption. After this setup completes:");
        println!("   1. Run: ./scripts/encrypt_seed.sh");
        println!("   2. Add to .env: SEED_PHRASE_ENCRYPTED=true");
        println!("   3. The server will prompt for GPG password on startup\n");
    } else {
        println!("\n⚠️  Seed phrase will be stored in PLAINTEXT.");
        println!("   Anyone with filesystem access can read it.\n");
    }

    println!("Press Enter to continue after you've backed up the seed phrase...");
    io::stdout().flush()?;
    let mut _confirm = String::new();
    io::stdin().read_line(&mut _confirm)?;

    // Store the seed phrase
    std::fs::write(secret_path, &phrase)?;
    std::fs::set_permissions(secret_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    Ok(phrase)
}

/// Load seed phrase, decrypting with GPG if needed
fn load_seed_phrase(secret_path: &PathBuf) -> anyhow::Result<String> {
    let encrypted = std::env::var("SEED_PHRASE_ENCRYPTED")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");

    if encrypted {
        // Check for encrypted file
        let enc_path = secret_path.with_extension("enc");
        if !enc_path.exists() {
            anyhow::bail!(
                "SEED_PHRASE_ENCRYPTED=true but {} not found. Run ./scripts/encrypt_seed.sh first.",
                enc_path.display()
            );
        }

        // Decrypt using GPG
        println!("Decrypting seed phrase with GPG...");
        let output = Command::new("gpg")
            .args(["--decrypt", "--quiet"])
            .arg(&enc_path)
            .output()?;

        if !output.status.success() {
            anyhow::bail!("GPG decryption failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    } else {
        // Read plaintext seed phrase
        if !secret_path.exists() {
            // First run - generate new seed phrase
            return generate_and_store_seed_phrase(secret_path);
        }

        let phrase = std::fs::read_to_string(secret_path)?;
        let phrase = phrase.trim();

        if phrase.is_empty() {
            anyhow::bail!(
                "Seed phrase file {} is empty. Delete it and restart to generate a new one.",
                secret_path.display()
            );
        }

        Ok(phrase.to_string())
    }
}

async fn generate_server_keys() -> anyhow::Result<()> {
    // Load environment
    load_env();

    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;

    // Load or generate seed phrase
    let secret_path = std::env::var("SECRET_PATH").unwrap_or_else(|_| "secrets/seed_phrase".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let password = load_seed_phrase(&secret_path_buf)?;

    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "default".to_string());

    // Initialize crypto utils
    let crypto = CryptoUtils::new(PathBuf::from(&keys_dir), password)?;

    // Check if keys already exist
    let priv_path = PathBuf::from(&keys_dir).join(format!("{}_private_key.enc", client_id));
    let pub_path = PathBuf::from(&keys_dir).join(format!("{}_public_key.asc", client_id));

    if priv_path.exists() && pub_path.exists() {
        println!("Server keys already exist for client_id: {}", client_id);
        println!("Private key: {}", priv_path.display());
        println!("Public key: {}", pub_path.display());
        return Ok(());
    }

    // Generate key pair for the server's client_id
    println!("Generating key pair for server client_id: {}", client_id);
    let _public_key = crypto.generate_key_pair(&client_id)?;

    println!("Server key pair generated successfully!");
    println!("Public key stored at: {}", pub_path.display());
    println!("Private key stored at: {}", priv_path.display());
    println!("Server can now sign messages during user registration.");

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Check if we should generate keys
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--generate" || args[1] == "-g") {
        return generate_server_keys().await;
    }

    // Load environment (including .env) and configure logging with defaults
    load_env();
    let log_file = std::env::var("LOG_FILE_PATH").unwrap_or_else(|_| "logs/server.log".to_string());
    // ensure the log file's directory exists
    if let Some(parent) = PathBuf::from(&log_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    init_logging(&log_file)?;

    // Ensure storage directories exist
    let db_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "storage/discovery.db".to_string());
    if let Some(parent) = PathBuf::from(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Ensure the DB file itself exists so SQLite can open it
    let db_path_buf = PathBuf::from(&db_path);
    if !db_path_buf.exists() {
        std::fs::File::create(&db_path_buf)?;
    }
    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;

    // Load or generate seed phrase
    let secret_path =
        std::env::var("SECRET_PATH").unwrap_or_else(|_| "secrets/seed_phrase".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let password = load_seed_phrase(&secret_path_buf)?;

    // Initialize client ID early (needed for keypair check)
    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "default".to_string());

    // Initialize utilities
    let crypto = CryptoUtils::new(PathBuf::from(&keys_dir), password.clone())?;

    // Check if server keypair exists, generate if missing (first run auto-setup)
    let priv_path = PathBuf::from(&keys_dir).join(format!("{}_private_key.enc", client_id));
    let pub_path = PathBuf::from(&keys_dir).join(format!("{}_public_key.asc", client_id));
    if !priv_path.exists() || !pub_path.exists() {
        log::info!("Server keypair not found for client_id '{}', generating...", client_id);
        crypto.generate_key_pair(&client_id)?;
        log::info!("Server keypair generated successfully.");
    }

    let db = DbUtils::new(&db_path).await?;

    // Initialize mixnet client storage path
    let storage_dir =
        std::env::var("NYM_SDK_STORAGE").unwrap_or_else(|_| format!("storage/{}", client_id));
    // Ensure mixnet SDK storage directory exists
    std::fs::create_dir_all(&storage_dir)?;
    let storage_paths = StoragePaths::new_from_dir(PathBuf::from(storage_dir))?;

    // Build and connect the mixnet client
    let builder = MixnetClientBuilder::new_with_default_storage(storage_paths).await?;
    let client_inner = builder.build()?.connect_to_mixnet().await?;
    let sender = client_inner.split_sender();
    let address = client_inner.nym_address();
    log::info!("Connected to mixnet. Nym Address: {}", address);

    // process incoming messages until shutdown signal or stream end
    let mut client_stream = client_inner;
    let mut message_utils = MessageUtils::new(client_id.clone(), sender, db, crypto);
    tokio::select! {
        _ = async {
            while let Some(msg) = client_stream.next().await {
                message_utils.process_received_message(msg).await;
            }
        } => {},
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down mixnet client.");
            client_stream.disconnect().await;
        }
    }
    Ok(())
}
