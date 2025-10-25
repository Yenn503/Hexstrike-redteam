#!/bin/bash
# Hexstrike Red Team - Start MCP Server
# Portable script that works from any location

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"
source hexstrike-env/bin/activate
echo "Starting Hexstrike MCP Server on http://localhost:8888"
echo "Press Ctrl+C to stop the server"
echo ""
python3 hexstrike_server.py
