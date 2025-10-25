#!/bin/bash
# Hexstrike Red Team - Master Installation Script
# Complete automated installation of all dependencies, tools, and configuration

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the parent directory (project root)
HEXSTRIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${RED}"
cat << "EOF"
╦ ╦╔═╗═╗ ╦╔═╗╔╦╗╦═╗╦╦╔═╗╔═╗  ╦═╗╔═╗╔╦╗  ╔╦╗╔═╗╔═╗╔╦╗
╠═╣║╣ ╔╩╦╝╚═╗ ║ ╠╦╝║╠╩╗║╣   ╠╦╝║╣  ║║   ║ ║╣ ╠═╣║║║
╩ ╩╚═╝╩ ╚═╚═╝ ╩ ╩╚═╩╩ ╩╚═╝  ╩╚═╚═╝═╩╝   ╩ ╚═╝╩ ╩╩ ╩
         Complete Installation & Setup
EOF
echo -e "${NC}"

echo ""
echo -e "${BLUE}=================================================="
echo "Hexstrike Red Team - Complete Installation"
echo "=================================================="
echo -e "${NC}"
echo ""
echo "Installation directory: $HEXSTRIKE_DIR"
echo ""
echo "This script will install:"
echo "  1. BOAZ mandatory system dependencies (MinGW, Wine, compilers)"
echo "  2. 70+ security tools (Network, Web, Binary, Forensics, OSINT, Cloud)"
echo "  3. Python virtual environment with all dependencies"
echo "  4. BOAZ LLVM obfuscators (Akira ~30 min, Pluto ~20 min)"
echo "  5. MCP configuration for Claude CLI/Desktop"
echo ""
echo -e "${YELLOW}Estimated total time: 60-90 minutes${NC}"
echo -e "${YELLOW}(mostly waiting for LLVM obfuscators to compile)${NC}"
echo ""
echo -e "${RED}This requires sudo access and will prompt for password.${NC}"
echo ""
read -p "Continue with installation? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 1
fi

cd "$HEXSTRIKE_DIR"

# Make all scripts executable
chmod +x "$SCRIPT_DIR/install_system_deps.sh"
chmod +x "$SCRIPT_DIR/install_security_tools.sh"
chmod +x "$SCRIPT_DIR/setup_hexstrike_venv.sh"
chmod +x "$SCRIPT_DIR/configure_mcp.sh"

# ===========================
# STEP 1: System Dependencies
# ===========================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  STEP 1/4: Installing System Dependencies  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

"$SCRIPT_DIR/install_system_deps.sh"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: System dependencies installation failed${NC}"
    exit 1
fi

# ===========================
# STEP 2: Security Tools
# ===========================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  STEP 2/4: Installing Security Tools       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

"$SCRIPT_DIR/install_security_tools.sh"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Security tools installation failed${NC}"
    exit 1
fi

# ===========================
# STEP 3: Python Environment
# ===========================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  STEP 3/4: Setting Up Python Environment  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

"$SCRIPT_DIR/setup_hexstrike_venv.sh"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Python environment setup failed${NC}"
    exit 1
fi

# ===========================
# STEP 4: MCP Configuration
# ===========================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  STEP 4/4: Configuring MCP Integration    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
sleep 2

"$SCRIPT_DIR/configure_mcp.sh"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: MCP configuration failed${NC}"
    exit 1
fi

# ===========================
# INSTALLATION COMPLETE
# ===========================
echo ""
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   ✓  INSTALLATION COMPLETE!                          ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo ""
echo -e "${BLUE}Installation Summary:${NC}"
echo ""
echo "✓ System Dependencies Installed:"
echo "  - Build tools (gcc, g++, cmake, nasm)"
echo "  - MinGW cross-compiler (x86_64-w64-mingw32)"
echo "  - Wine (wine64, wine32)"
echo "  - Python 3 + pip + venv"
echo "  - Chromium browser + ChromeDriver"
echo ""
echo "✓ Security Tools Installed (70+ tools):"
echo "  - Network & Reconnaissance (9 tools)"
echo "  - Web Application Security (11 tools)"
echo "  - Authentication & Password (5 tools)"
echo "  - Binary Analysis & RE (13 tools)"
echo "  - Metasploit Framework + msfvenom"
echo "  - Digital Forensics (10 tools)"
echo "  - OSINT & Intelligence (4 tools)"
echo "  - Cloud Security (7 tools)"
echo "  - Niche/Bonus Tools (10 tools)"
echo ""
echo "✓ Python Environment:"
echo "  - Virtual environment: hexstrike-env"
echo "  - Main dependencies installed"
echo "  - BOAZ dependencies installed"
echo "  - LLVM obfuscators compiled (Akira + Pluto)"
echo ""
echo "✓ MCP Configuration:"
echo "  - Claude Desktop: ~/.config/Claude/claude_desktop_config.json"
echo "  - Claude CLI: ~/.config/claude-cli/config.json"
echo ""
echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
echo -e "${YELLOW}        NEXT STEPS TO USE HEXSTRIKE${NC}"
echo -e "${YELLOW}═════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}1. Start the Hexstrike MCP Server:${NC}"
echo "   cd $HEXSTRIKE_DIR"
echo "   ./start_server.sh"
echo ""
echo -e "${GREEN}2. Test the server (in a new terminal):${NC}"
echo "   ./test_server.sh"
echo ""
echo -e "${GREEN}3. Restart Claude Desktop/CLI to load MCP config${NC}"
echo ""
echo -e "${GREEN}4. Use Hexstrike MCP tools in Claude:${NC}"
echo "   Example prompts:"
echo "   • 'Use nmap_scan to scan example.com'"
echo "   • 'List available BOAZ loaders'"
echo "   • 'Generate a BOAZ payload with syscall loader'"
echo "   • 'Run nuclei vulnerability scan'"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "  - README: $HEXSTRIKE_DIR/README.md"
echo "  - BOAZ Guide: Check README for BOAZ workflow"
echo "  - MCP Tools: 155+ tools available via MCP"
echo ""
echo -e "${YELLOW}Happy Hacking! 🔥${NC}"
echo ""
