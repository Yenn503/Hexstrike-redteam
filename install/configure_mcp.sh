#!/bin/bash
# Hexstrike Red Team - MCP Configuration Script
# Part 4: Configure MCP for Claude Desktop and Claude CLI

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the parent directory (project root)
HEXSTRIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=================================================="
echo "Configuring MCP for Hexstrike Red Team"
echo "=================================================="
echo ""
echo "Installation directory: $HEXSTRIKE_DIR"
echo ""

# ===========================
# Configure Claude Desktop
# ===========================
echo -e "${GREEN}[1/2] Configuring Claude Desktop...${NC}"

CLAUDE_CONFIG_DIR="$HOME/.config/Claude"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"

# Create config directory if it doesn't exist
mkdir -p "$CLAUDE_CONFIG_DIR"

# Check if config file exists
if [ -f "$CLAUDE_CONFIG_FILE" ]; then
    echo "  → Backing up existing configuration..."
    cp "$CLAUDE_CONFIG_FILE" "$CLAUDE_CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo "  ✓ Backup created"
fi

# Create or update configuration
echo "  → Writing MCP configuration..."
cat > "$CLAUDE_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "$HEXSTRIKE_DIR/hexstrike-env/bin/python3",
      "args": [
        "$HEXSTRIKE_DIR/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "HexStrike AI v6.0 - 155+ Security Tools, BOAZ Red Team Payload Evasion",
      "timeout": 300
    }
  }
}
EOF

echo "  ✓ Claude Desktop configuration written"
echo "  Location: $CLAUDE_CONFIG_FILE"

# ===========================
# Configure Claude CLI
# ===========================
echo ""
echo -e "${GREEN}[2/2] Configuring Claude CLI...${NC}"

CLAUDE_CLI_CONFIG_DIR="$HOME/.config/claude-cli"
CLAUDE_CLI_CONFIG_FILE="$CLAUDE_CLI_CONFIG_DIR/config.json"

# Create config directory if it doesn't exist
mkdir -p "$CLAUDE_CLI_CONFIG_DIR"

# Check if config file exists
if [ -f "$CLAUDE_CLI_CONFIG_FILE" ]; then
    echo "  → Backing up existing configuration..."
    cp "$CLAUDE_CLI_CONFIG_FILE" "$CLAUDE_CLI_CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo "  ✓ Backup created"
fi

# Create or update configuration
echo "  → Writing MCP configuration..."
cat > "$CLAUDE_CLI_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "$HEXSTRIKE_DIR/hexstrike-env/bin/python3",
      "args": [
        "$HEXSTRIKE_DIR/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "HexStrike AI v6.0 - 155+ Security Tools, BOAZ Red Team Payload Evasion",
      "timeout": 300
    }
  }
}
EOF

echo "  ✓ Claude CLI configuration written"
echo "  Location: $CLAUDE_CLI_CONFIG_FILE"

# ===========================
# Summary
# ===========================
echo ""
echo "=================================================="
echo "MCP Configuration Complete!"
echo "=================================================="
echo ""
echo -e "${BLUE}Configuration Details:${NC}"
echo ""
echo "✓ Claude Desktop Config:"
echo "  $CLAUDE_CONFIG_FILE"
echo ""
echo "✓ Claude CLI Config:"
echo "  $CLAUDE_CLI_CONFIG_FILE"
echo ""
echo "✓ Hexstrike Directory:"
echo "  $HEXSTRIKE_DIR"
echo ""
echo "✓ Python Interpreter:"
echo "  $HEXSTRIKE_DIR/hexstrike-env/bin/python3"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "  1. Restart Claude Desktop/CLI to load the new configuration"
echo "  2. Make sure the Hexstrike server is running (./start_server.sh)"
echo "  3. The server must be running on http://localhost:8888"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "  1. Start server: cd $HEXSTRIKE_DIR && ./start_server.sh"
echo "  2. Test server: ./test_server.sh"
echo "  3. Restart Claude Desktop/CLI"
echo "  4. Use Hexstrike MCP tools in your AI conversations!"
echo ""
