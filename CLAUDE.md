# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**nymstr-server** is a Rust-based discovery and message relay service for nymCHAT clients using the Nym Mixnet SDK. It provides user registration, authentication, and encrypted message routing over the Nym privacy network.

## Commands

### Build & Run
- `cargo build --release` - Build the project in release mode
- `cargo run --release` - Run the server
- `cargo run --release -- --generate` or `cargo run --release -- -g` - Generate server keypair

### Testing
- `cargo test` - Run all tests across all modules
- `cargo test --test <test_name>` - Run a specific test
- `RUST_LOG=debug cargo test` - Run tests with debug logging

### Development
- `cargo check` - Quick compile check without building
- `RUST_LOG=debug cargo run` - Run with debug logging
- `RUST_LOG=trace cargo run` - Run with trace logging (most verbose)

## Architecture

### Core Components

**main.rs** - Entry point that:
- Handles CLI args (--generate flag for keypair generation)
- Initializes environment, logging, and storage directories
- Connects to Nym mixnet and processes incoming messages via `MessageUtils`
- Uses `tokio::select!` to handle shutdown signals gracefully

**crypto_utils.rs** - PGP-based cryptography:
- Migrated from OpenSSL ECDSA to PGP (pgp crate) for key management
- Uses BIP39 24-word seed phrase (256-bit entropy) as master password
- Encrypts private keys with AES-256-GCM using PBKDF2-derived keys from seed phrase
- Generates RSA-2048 keypairs for users and server
- Signs messages by hashing with SHA-256 first, then creating PGP signatures
- Verifies signatures supporting both armored and base64-encoded formats
- All keys stored in `KEYS_DIR` (default: `storage/keys/`)

**db_utils.rs** - SQLite database interface:
- Uses SQLx 0.8 with async/await
- Schema: `users` table (username, publicKey, senderTag) and `groups` table
- WAL mode and foreign keys enabled
- Key methods: `add_user()`, `get_user_by_username()`, `update_user_field()`
- Usernames are primary keys

**message_utils.rs** - Message routing and protocol handler:
- Supports both **legacy format** (backward compatibility) and **unified format** (new protocol with `type` and `action` fields)
- Handles authentication flows: registration and login with nonce-based challenges
- Routes messages between users via AnonymousSenderTag (ephemeral Nym addresses)
- Supports MLS encrypted messages: extracts `conversation_id` and `mls_message` from payload
- Server signs all responses using its own keypair (client_id)
- In-memory HashMaps track pending registrations/logins by sender_tag

**env_loader.rs** - Simple wrapper around `dotenvy` to load `.env` files

**log_config.rs** - Configures fern logger:
- Colored console output (red=error, yellow=warn, green=info, cyan=debug)
- Log level controlled by `RUST_LOG` env var (default: Info)
- Logs to both file and stdout with RFC3339 timestamps

### Seed Phrase Management

**First Run Behavior:**
- Generates a BIP39 24-word mnemonic (256 bits of entropy)
- Displays seed phrase ONCE to user for backup
- Prompts user about GPG encryption preference
- Stores in `secrets/seed_phrase` (plaintext) or `secrets/seed_phrase.enc` (GPG-encrypted)

**Seed Phrase Loading** (see `load_seed_phrase()` in main.rs):
- Checks `SEED_PHRASE_ENCRYPTED` env var
- If true: decrypts `secrets/seed_phrase.enc` using GPG via shell command
- If false: reads plaintext from `secrets/seed_phrase`
- Empty or missing seed phrase triggers generation flow

**Optional GPG Encryption:**
- Use `scripts/encrypt_seed.sh` to encrypt existing seed phrase
- Uses AES256 symmetric encryption
- Securely deletes plaintext version with `shred` or `srm`
- Server prompts for GPG password on startup when encrypted

**Security Model:**
- Seed phrase → PBKDF2 (100k iterations) → AES-256-GCM key
- Each private key has unique salt and IV
- User must backup seed phrase - file loss without backup = unrecoverable

### Authentication Flow

1. **Registration**: Client sends `register` → Server responds with `challenge` (nonce) → Client signs nonce → Server verifies signature → User added to DB
2. **Login**: Client sends `login` → Server responds with `challenge` (nonce) → Client signs nonce → Server verifies signature and updates senderTag

Username validation: alphanumeric, `-`, and `_` only.

### Message Format

**Unified Format** (preferred):
```json
{
  "type": "message|response",
  "action": "send|query|register|login|...",
  "sender": "username",
  "recipient": "username",
  "payload": { ... },
  "signature": "base64_signature",
  "timestamp": "RFC3339"
}
```

**Legacy Format** (backward compatibility):
```json
{
  "action": "send|query|...",
  "content": "...",
  "signature": "..."
}
```

### Nym Mixnet Integration

- Uses `nym-sdk` from the Nym GitHub repository (master branch)
- Storage paths configured via `NYM_SDK_STORAGE` (defaults to `storage/{NYM_CLIENT_ID}`)
- Messages routed using AnonymousSenderTag (SURB-based replies)
- Client connects once at startup and maintains persistent connection until Ctrl+C

## Configuration

Environment variables (see `.env.example`):
- `NYM_CLIENT_ID` - Unique identifier for this discovery node (default: `default`)
- `NYM_SDK_STORAGE` - Nym SDK storage directory (default: `storage/${NYM_CLIENT_ID}`)
- `DATABASE_PATH` - SQLite database path (default: `storage/discovery.db`)
- `KEYS_DIR` - Directory for PGP keys (default: `storage/keys`)
- `SECRET_PATH` - Seed phrase file path (default: `secrets/seed_phrase`)
- `SEED_PHRASE_ENCRYPTED` - Whether seed phrase is GPG-encrypted (default: `false`)
- `LOG_FILE_PATH` - Log file path (default: `logs/server.log`)
- `RUST_LOG` - Log level (trace|debug|info|warn|error, default: `info`)

Setup:
```bash
cp .env.example .env
cargo run --release  # Generates seed phrase on first run
# Back up the displayed seed phrase!
# Optionally: ./scripts/encrypt_seed.sh
cargo run --release -- --generate  # Generate server keys
cargo run --release  # Start server
```

**First Run:** Server auto-generates BIP39 seed phrase, displays it once for backup, and stores in `secrets/seed_phrase`.

**Optional Encryption:** Run `./scripts/encrypt_seed.sh` to encrypt with GPG, then set `SEED_PHRASE_ENCRYPTED=true` in `.env`.

## Testing

All modules have comprehensive test coverage:
- Unit tests use `tempfile` for isolated temporary directories
- Database tests use `tokio-test` and async test macros
- Crypto tests verify key generation, encryption/decryption, signing/verification
- Tests clean up after themselves (removing temp env vars)

## Important Notes

- **Signature verification always hashes messages with SHA-256 before verifying** (crypto_utils.rs:138-144)
- Server must generate its own keypair before first run (use `--generate` flag)
- SenderTags are updated on login to handle ephemeral Nym client addresses
- Edition is set to `2024` in Cargo.toml (uses latest Rust edition)
- License: Apache-2.0
