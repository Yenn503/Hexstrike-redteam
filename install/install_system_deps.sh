#!/bin/bash
# Hexstrike Red Team - System Dependencies Installation
# Part 1: BOAZ Mandatory System Dependencies

echo "=================================================="
echo "Installing BOAZ Mandatory System Dependencies"
echo "=================================================="

# Enable 32-bit architecture for wine32
echo "[*] Enabling 32-bit architecture..."
sudo dpkg --add-architecture i386

# Update package lists
echo "[*] Updating package lists..."
sudo apt update

# Install build tools
echo "[*] Installing build tools..."
sudo apt install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    nasm \
    curl \
    unzip \
    wget

# Install Windows cross-compilation tools
echo "[*] Installing MinGW cross-compiler toolchain..."
sudo apt install -y \
    mingw-w64 \
    mingw-w64-tools \
    gcc-mingw-w64 \
    g++-mingw-w64 \
    binutils-mingw-w64

# Install Wine for testing payloads
echo "[*] Installing Wine..."
sudo apt install -y \
    wine \
    wine64 \
    wine32:i386

# Install compilers and libraries
echo "[*] Installing compilers and libraries..."
sudo apt install -y \
    clang \
    gcc \
    g++ \
    gcc-multilib \
    g++-multilib \
    zlib1g-dev

# Install Python environment
echo "[*] Installing Python environment..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Install code signing tool
echo "[*] Installing osslsigncode..."
sudo apt install -y osslsigncode

# Install browser for web automation
echo "[*] Installing Chromium browser..."
sudo apt install -y \
    chromium-browser \
    chromium-chromedriver

# Install Go (required for Mangle)
echo "[*] Installing Go..."
sudo apt install -y golang-go

echo ""
echo "=================================================="
echo "System Dependencies Installation Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Run ./install_security_tools.sh to install pentesting tools"
echo "2. Run ./setup_hexstrike_venv.sh to set up Python environment"
echo ""
