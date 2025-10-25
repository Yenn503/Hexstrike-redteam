#!/bin/bash
# Hexstrike Red Team - Python Virtual Environment Setup
# Part 3: Python venv, dependencies, and BOAZ setup

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the parent directory (project root)
HEXSTRIKE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_NAME="hexstrike-env"

echo "=================================================="
echo "Setting Up Hexstrike Python Virtual Environment"
echo "=================================================="
echo ""
echo "Installation directory: $HEXSTRIKE_DIR"
echo "Virtual environment: $VENV_NAME"
echo ""

cd "$HEXSTRIKE_DIR"

# Step 1: Create virtual environment
echo "[1/5] Creating Python virtual environment..."
if [ -d "$VENV_NAME" ]; then
    echo "  → Virtual environment already exists, removing old one..."
    rm -rf "$VENV_NAME"
fi
python3 -m venv "$VENV_NAME"
echo "  ✓ Virtual environment created"

# Step 2: Activate virtual environment
echo ""
echo "[2/5] Activating virtual environment..."
source "$VENV_NAME/bin/activate"
echo "  ✓ Virtual environment activated"

# Step 3: Upgrade pip
echo ""
echo "[3/5] Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo "  ✓ pip upgraded"

# Step 4: Install main Python dependencies
echo ""
echo "[4/5] Installing Hexstrike Python dependencies..."
echo "  → Installing from requirements.txt..."
pip install -r requirements.txt
echo "  ✓ Main dependencies installed"

# Step 5: Install BOAZ dependencies
echo ""
echo "  → Installing BOAZ Python dependencies..."
cd BOAZ_beta
pip install -r requirements.txt
echo "  ✓ BOAZ Python dependencies installed"

# Step 6: Run BOAZ requirements.sh (MANDATORY)
echo ""
echo "[5/5] Running BOAZ system requirements script..."
echo ""
echo "========================================"
echo "IMPORTANT: BOAZ System Dependencies"
echo "========================================"
echo "This will install and compile:"
echo "  - Akira LLVM Obfuscator (~30 min compile)"
echo "  - Pluto LLVM Obfuscator (~20 min compile)"
echo "  - Mangle (binary signature tool)"
echo "  - SysWhispers2 (syscall generator)"
echo "  - pyMetaTwin (metadata tool)"
echo ""
echo "Total estimated time: 50-60 minutes"
echo ""
echo "Starting BOAZ installation..."
echo ""

bash requirements.sh

cd ..

echo ""
echo "=================================================="
echo "Hexstrike Python Environment Setup Complete!"
echo "=================================================="
echo ""
echo "Virtual environment location: $HEXSTRIKE_DIR/$VENV_NAME"
echo ""
echo "To activate the environment manually:"
echo "  source $HEXSTRIKE_DIR/$VENV_NAME/bin/activate"
echo ""
echo "To start Hexstrike server:"
echo "  source $HEXSTRIKE_DIR/$VENV_NAME/bin/activate"
echo "  python3 hexstrike_server.py"
echo ""
echo "Next step:"
echo "  Run $SCRIPT_DIR/configure_mcp.sh to set up Claude CLI/Desktop MCP configuration"
echo ""
