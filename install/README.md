# Hexstrike Red Team - Installation Scripts

This directory contains all installation and setup scripts for Hexstrike Red Team.

## 📋 Scripts Overview

### Main Installation Script

- **`install_all.sh`** - Master installation script that runs everything in sequence
  - Installs system dependencies
  - Installs 70+ security tools
  - Sets up Python virtual environment
  - Compiles BOAZ LLVM obfuscators
  - Configures MCP for Claude Desktop/CLI

### Individual Component Scripts

1. **`install_system_deps.sh`** - System-level dependencies
   - Build tools (gcc, g++, cmake, nasm)
   - MinGW cross-compiler
   - Wine (for testing Windows payloads)
   - Python development tools
   - Chromium browser for web automation

2. **`install_security_tools.sh`** - 70+ penetration testing tools
   - Network & Reconnaissance (9 tools)
   - Web Application Security (11 tools)
   - Authentication & Password (5 tools)
   - Binary Analysis & RE (13 tools)
   - Metasploit Framework
   - Digital Forensics (10 tools)
   - OSINT & Intelligence (4 tools)
   - Cloud Security (7 tools)
   - Bonus/Niche Tools (10 tools)

3. **`setup_hexstrike_venv.sh`** - Python environment setup
   - Creates Python virtual environment
   - Installs Python dependencies
   - Installs BOAZ dependencies
   - Compiles LLVM obfuscators (Akira + Pluto)

4. **`configure_mcp.sh`** - MCP configuration
   - Configures Claude Desktop
   - Configures Claude CLI
   - Creates portable configuration with dynamic paths

### Utility Scripts

- **`start_server.sh`** - Start the Hexstrike MCP server
- **`test_server.sh`** - Test if the server is running correctly

## 🚀 Quick Start

### Complete Installation (Recommended)

```bash
cd install
./install_all.sh
```

This runs all installation steps in the correct order.

### Step-by-Step Installation

If you prefer more control:

```bash
cd install

# Step 1: Install system dependencies (requires sudo)
./install_system_deps.sh

# Step 2: Install security tools (requires sudo)
./install_security_tools.sh

# Step 3: Setup Python environment and BOAZ (~60 min)
./setup_hexstrike_venv.sh

# Step 4: Configure MCP for Claude
./configure_mcp.sh
```

## ⚙️ Script Features

### Portable Design

All scripts use **dynamic path detection** - no hardcoded paths!

```bash
# Scripts automatically detect their location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEXSTRIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
```

This means:
- ✅ Works regardless of where you clone the repository
- ✅ Works for all users on any system
- ✅ No need to edit paths manually

### Error Handling

- Scripts exit on error (`set -e`)
- Each step validates before proceeding
- Backups created for existing configurations
- Clear error messages for troubleshooting

### Resumable Installation

If installation fails partway through:
1. Fix the issue (missing dependencies, network issues, etc.)
2. Re-run the individual script that failed
3. Continue from where you left off

## 📝 Installation Notes

### Time Requirements

- **System Dependencies**: ~5-10 minutes
- **Security Tools**: ~10-20 minutes (depends on network speed)
- **Python + BOAZ**: ~50-60 minutes (LLVM compilation)
- **MCP Config**: <1 minute
- **Total**: 60-90 minutes

### Disk Space

- System tools: ~2GB
- Security tools: ~5GB
- BOAZ obfuscators: ~15GB (akira_built + Pluto)
- Python packages: ~2GB
- **Total**: ~24GB

### System Requirements

- **OS**: Linux (Debian/Ubuntu) or Kali Linux
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB+ recommended for LLVM compilation
- **CPU**: Multi-core recommended for faster compilation
- **Sudo Access**: Required for system package installation

## 🔧 Configuration Details

### MCP Configuration Files

After running `configure_mcp.sh`, MCP configs are created at:

- **Claude Desktop**: `~/.config/Claude/claude_desktop_config.json`
- **Claude CLI**: `~/.config/claude-cli/config.json`

Both configurations use the same structure:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "/path/to/hexstrike-env/bin/python3",
      "args": [
        "/path/to/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "HexStrike AI v6.0 - 155+ Security Tools, BOAZ Red Team Payload Evasion",
      "timeout": 300
    }
  }
}
```

Paths are automatically detected and configured correctly.

## 🐛 Troubleshooting

### Permission Denied

```bash
chmod +x install/*.sh
```

### Script Not Found

Make sure you're in the correct directory:

```bash
cd /path/to/Hexstrike-redteam
cd install
./install_all.sh
```

### LLVM Compilation Fails

- Requires 4GB+ RAM
- Takes 50-60 minutes
- Check build logs in BOAZ_beta directory

### Tools Not Installing

- Check internet connection
- Some tools require specific package sources
- Run with verbose output to diagnose

### MCP Not Working

1. Verify config files exist in `~/.config/Claude/` or `~/.config/claude-cli/`
2. Restart Claude Desktop/CLI completely
3. Check server is running: `./test_server.sh`

## 🎯 After Installation

### Start the Server

From the project root:

```bash
./start_server.sh
```

Or from the install directory:

```bash
cd ..
./start_server.sh
```

### Test the Server

```bash
./test_server.sh
```

Expected output:
```
✓ Server is running!

Server Response:
{
  "status": "ok",
  "version": "6.0",
  ...
}
```

### Use Hexstrike

1. Open Claude Desktop or Claude CLI
2. Start a conversation
3. Use Hexstrike MCP tools:
   - "Use nmap_scan to scan example.com"
   - "List available BOAZ loaders"
   - "Generate a BOAZ payload"
   - "Run nuclei vulnerability scan"

## 📚 Additional Resources

- **Main Documentation**: `../README.md`
- **Quick Start**: `../INSTALL_NOW.md`
- **BOAZ Guide**: See README for payload generation workflow
- **MCP Tools**: 155+ tools available via MCP protocol

## 🤝 Contributing

To improve installation scripts:

1. Test on multiple systems
2. Add error handling
3. Improve detection logic
4. Update documentation

## 📄 License

Same license as the main Hexstrike Red Team project.
