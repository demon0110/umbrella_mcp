#!/bin/bash
cd "$(dirname "$0")"
echo "Creating venv..."
python3 -m venv .venv
echo "Installing dependencies..."
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install fastmcp
echo ""
echo "=== Setup complete ==="
echo "venv Python: $(python --version)"
echo "fastmcp: $(which fastmcp)"
echo ""
echo "Edit .env to add your CISCO_CLIENT_ID and CISCO_CLIENT_SECRET"
echo "Then restart Claude Desktop"
