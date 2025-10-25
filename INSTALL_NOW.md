# Quick Installation Guide for Hexstrike Red Team

## One-Command Installation

Run this command from the project directory:

```bash
cd install
./install_all.sh
```

When prompted, press `y` to confirm.

## What Gets Installed

The installation script will automatically:

1. **System Dependencies** - MinGW cross-compiler, Wine, NASM, build tools
2. **70+ Security Tools** - Network, Web, Binary, Forensics, OSINT, Cloud tools
3. **Python Environment** - Virtual environment with all required dependencies
4. **BOAZ Framework** - LLVM obfuscators (Akira + Pluto, ~50 minutes compile time)
5. **MCP Configuration** - Automatic setup for Claude Desktop and Claude CLI

## Installation Time

- **Quick tools**: ~10-15 minutes
- **LLVM obfuscators**: ~50-60 minutes (Akira + Pluto compilation)
- **Total**: 60-90 minutes

## After Installation

1. **Start the server**:
   ```bash
   ./start_server.sh
   ```

2. **Test the server** (in a new terminal):
   ```bash
   ./test_server.sh
   ```

3. **Restart Claude Desktop/CLI** to load the MCP configuration

4. **Start using Hexstrike** in your AI conversations!

## Individual Installation Steps

If you prefer to install components separately:

```bash
cd install

# Step 1: System dependencies
./install_system_deps.sh

# Step 2: Security tools (70+)
./install_security_tools.sh

# Step 3: Python environment + BOAZ
./setup_hexstrike_venv.sh

# Step 4: MCP configuration
./configure_mcp.sh
```

## Troubleshooting

- **Permission denied**: Run `chmod +x install/*.sh` to make scripts executable
- **MCP not working**: Restart Claude Desktop/CLI after installation
- **Server not starting**: Check that port 8888 is available

## Requirements

- **OS**: Linux (Debian/Ubuntu recommended) or Kali Linux
- **Python**: 3.8 or higher
- **Disk Space**: ~20GB (mostly for LLVM obfuscators)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Sudo Access**: Required for installing system packages

## Support

- **Documentation**: See README.md for full documentation
- **Issues**: Report at GitHub issues page
- **BOAZ Guide**: See README.md for payload generation workflow
