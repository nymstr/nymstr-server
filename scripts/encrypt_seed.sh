#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Seed Phrase Encryption Script${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Get SECRET_PATH from .env or use default
SECRET_PATH=$(grep -E '^SECRET_PATH=' .env 2>/dev/null | cut -d'=' -f2 || echo "secrets/seed_phrase")

if [ ! -f "$SECRET_PATH" ]; then
    echo -e "${RED}Error: Seed phrase file not found at: $SECRET_PATH${NC}"
    echo "Please run the server first to generate a seed phrase."
    exit 1
fi

if [ -f "${SECRET_PATH}.enc" ]; then
    echo -e "${YELLOW}Warning: Encrypted seed phrase already exists at: ${SECRET_PATH}.enc${NC}"
    read -p "Overwrite it? (y/N): " overwrite
    if [ "$overwrite" != "y" ] && [ "$overwrite" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi
fi

echo -e "${GREEN}Found plaintext seed phrase at: $SECRET_PATH${NC}"
echo ""
echo "You will be prompted to enter a password to encrypt the seed phrase."
echo "Remember this password - you'll need it every time the server starts."
echo ""

# Encrypt with GPG
if ! gpg --symmetric --cipher-algo AES256 --output "${SECRET_PATH}.enc" "$SECRET_PATH"; then
    echo -e "${RED}Error: GPG encryption failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Seed phrase encrypted successfully!${NC}"
echo -e "  Encrypted file: ${SECRET_PATH}.enc"
echo ""

# Securely delete plaintext version
echo "Securely deleting plaintext seed phrase..."
if command -v shred &> /dev/null; then
    shred -u "$SECRET_PATH"
    echo -e "${GREEN}✓ Plaintext seed phrase securely deleted with shred${NC}"
elif command -v srm &> /dev/null; then
    srm "$SECRET_PATH"
    echo -e "${GREEN}✓ Plaintext seed phrase securely deleted with srm${NC}"
else
    # Fallback: overwrite with random data before deletion
    dd if=/dev/urandom of="$SECRET_PATH" bs=1 count=$(stat -f%z "$SECRET_PATH" 2>/dev/null || stat -c%s "$SECRET_PATH") conv=notrunc 2>/dev/null
    rm "$SECRET_PATH"
    echo -e "${YELLOW}⚠  Plaintext seed phrase deleted (secure deletion tool not available)${NC}"
fi

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Next Steps:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "1. Add to your .env file:"
echo -e "   ${GREEN}SEED_PHRASE_ENCRYPTED=true${NC}"
echo ""
echo "2. Restart the server. You'll be prompted for your GPG password."
echo ""
echo -e "${RED}IMPORTANT: If you lose your GPG password, you will need your${NC}"
echo -e "${RED}backed-up seed phrase to recover access to encrypted keys.${NC}"
echo ""
