#!/bin/bash
# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the parent directory (project root)
HEXSTRIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$HEXSTRIKE_DIR"
source hexstrike-env/bin/activate
echo "Starting Hexstrike MCP Server on http://localhost:8888"
python3 hexstrike_server.py
