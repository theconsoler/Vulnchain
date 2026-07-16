#!/bin/bash
set -e

echo "======================================"
echo "  VulnChain -- Starting Up"
echo "======================================"

# Verify required environment variables are set
if [ -z "$SECRET_KEY" ]; then
    echo "ERROR: SECRET_KEY environment variable is not set."
    echo "Copy .env.example to .env and fill in the values."
    exit 1
fi

if [ -z "$JWT_SECRET_KEY" ]; then
    echo "ERROR: JWT_SECRET_KEY environment variable is not set."
    exit 1
fi

# Create default admin user if VULNCHAIN_USER and VULNCHAIN_PASSWORD are set
# and no users exist yet
if [ -n "$VULNCHAIN_USER" ] && [ -n "$VULNCHAIN_PASSWORD" ]; then
    echo "[*] Creating default user: $VULNCHAIN_USER"
    python create_user.py \
        --username "$VULNCHAIN_USER" \
        --password "$VULNCHAIN_PASSWORD" 2>/dev/null || \
        echo "[i] User already exists, skipping."
fi

echo "[+] Starting VulnChain on port 5000..."
echo "[+] Open http://localhost:5000 in your browser"
echo ""

# Start Flask
exec python run.py
