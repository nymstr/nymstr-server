# nymstr-server

Discovery node and P2P message relay service for the Nymstr messaging system, built on the [Nym mixnet](https://nymtech.net/).

## What it does

- User registration and directory lookups
- P2P message routing via SURB
- Group server discovery
- MLS key package exchange

## Quick Start

```bash
cp .env.example .env
cargo run --release
```

On first run, the server generates a BIP39 seed phrase. **Write it down** - it protects all encrypted keys.

To generate server keys manually:
```bash
cargo run --release -- --generate
```

## Configuration

See `.env.example` for all options. Key variables:

- `NYM_CLIENT_ID` - Unique identifier (default: `default`)
- `DATABASE_PATH` - SQLite database (default: `storage/discovery.db`)
- `KEYS_DIR` - PGP keys directory (default: `storage/keys`)

## License

GNU GPLv3.0
