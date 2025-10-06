# Nym Discovery Node (Rust)

A discovery and message relay service for nymCHAT clients, fully rewritten in Rust using the Nym Mixnet SDK.

## Configuration

### Quick Start

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Run the server - it will automatically generate a BIP39 seed phrase on first run:
```bash
cargo run --release
```

On first run, the server will:
- Display a 24-word seed phrase
- Prompt you to back it up (write it down!)
- Ask if you want to encrypt it with a password
- Store it in `secrets/seed_phrase`

**⚠️ IMPORTANT**: Write down your seed phrase! It protects all encrypted keys. If you lose both the seed phrase file AND your backup, encrypted keys cannot be recovered.

### Optional: Encrypt Your Seed Phrase

For enhanced security, encrypt your seed phrase with GPG:

```bash
./scripts/encrypt_seed.sh
```

This will:
- Encrypt `secrets/seed_phrase` with a password of your choice
- Create `secrets/seed_phrase.enc`
- Securely delete the plaintext version
- Prompt you to add `SEED_PHRASE_ENCRYPTED=true` to `.env`

When encrypted, you'll need to enter your GPG password each time the server starts.

### Environment Variables

Edit `.env` to customize these variables:

- `NYM_CLIENT_ID`: Unique identifier for this discovery node (default: `default`)
- `NYM_SDK_STORAGE`: Path to the Nym SDK storage directory (default: `storage/${NYM_CLIENT_ID}`)
- `DATABASE_PATH`: Path to the SQLite database file (default: `storage/discovery.db`)
- `KEYS_DIR`: Directory for user encryption keys (default: `storage/keys`)
- `SECRET_PATH`: Path to the seed phrase file (default: `secrets/seed_phrase`)
- `SEED_PHRASE_ENCRYPTED`: Whether seed phrase is GPG-encrypted (default: `false`)
- `LOG_FILE_PATH`: File path for log output (default: `logs/server.log`)
- `RUST_LOG`: Log level - `trace`, `debug`, `info`, `warn`, or `error` (default: `info`)

## Running Locally

Ensure you have Rust toolchain installed, then:

```bash
cargo run --release
```

This will start the discovery node, connect to the Nym Mixnet, and begin processing incoming messages.

Logs printed to the console are colorized by log level for easier readability.

## Environment Variables

See `.env.example` for details on required variables.

## License

This project is licensed under the Apache-2.0 License.