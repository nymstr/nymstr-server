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
use tokio_stream::StreamExt;

async fn generate_server_keys() -> anyhow::Result<()> {
    // Load environment
    load_env();

    let keys_dir = std::env::var("KEYS_DIR").unwrap_or_else(|_| "storage/keys".to_string());
    std::fs::create_dir_all(&keys_dir)?;

    let secret_path = std::env::var("SECRET_PATH").unwrap_or_else(|_| "secrets/encryption_password".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !secret_path_buf.exists() {
        std::fs::write(&secret_path_buf, "")?;
    }
    let password = std::fs::read_to_string(&secret_path_buf)?.trim().to_string();

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
    let public_key = crypto.generate_key_pair(&client_id)?;

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

    // Load encryption password (default path if unset), creating file if needed
    let secret_path =
        std::env::var("SECRET_PATH").unwrap_or_else(|_| "secrets/encryption_password".to_string());
    let secret_path_buf = PathBuf::from(&secret_path);
    if let Some(parent) = secret_path_buf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !secret_path_buf.exists() {
        std::fs::write(&secret_path_buf, "")?;
    }
    let password = std::fs::read_to_string(&secret_path_buf)?
        .trim()
        .to_string();

    // Initialize utilities
    let crypto = CryptoUtils::new(PathBuf::from(&keys_dir), password.clone())?;
    let db = DbUtils::new(&db_path).await?;

    // Initialize mixnet client storage path and client ID (with defaults)
    let client_id = std::env::var("NYM_CLIENT_ID").unwrap_or_else(|_| "default".to_string());
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
