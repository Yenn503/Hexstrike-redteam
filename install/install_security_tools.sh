#!/bin/bash
# Hexstrike Red Team - Security Tools Installation
# Part 2: Essential Security Tools (60+) + Niche Tools (10+)

echo "=================================================="
echo "Installing Security Tools for Hexstrike Red Team"
echo "=================================================="
echo ""
echo "This will install 70+ security tools:"
echo "  - Network & Reconnaissance (9 tools)"
echo "  - Web Application Security (11 tools)"
echo "  - Authentication & Password (5 tools)"
echo "  - Binary Analysis & RE (13 tools)"
echo "  - Metasploit Framework (1 tool)"
echo "  - Digital Forensics (10 tools)"
echo "  - OSINT (4 tools)"
echo "  - Cloud Security (7 tools)"
echo "  - Niche/Bonus Tools (10 tools)"
echo ""

# Update package lists
echo "[*] Updating package lists..."
sudo apt update

# ===========================
# NETWORK & RECONNAISSANCE
# ===========================
echo ""
echo "[*] Installing Network & Reconnaissance Tools..."
sudo apt install -y nmap masscan

# AutoRecon (Python tool)
echo "[*] Installing AutoRecon..."
if ! command -v autorecon &> /dev/null; then
    sudo apt install -y python3-pip pipx
    pipx install git+https://github.com/Tib3rius/AutoRecon.git --force || \
    sudo pip3 install git+https://github.com/Tib3rius/AutoRecon.git --break-system-packages || \
    {
        if [ ! -d /opt/AutoRecon ]; then
            sudo git clone https://github.com/Tib3rius/AutoRecon.git /opt/AutoRecon
            sudo pip3 install -r /opt/AutoRecon/requirements.txt --break-system-packages
            sudo chmod +x /opt/AutoRecon/src/autorecon/autorecon.py
            sudo ln -sf /opt/AutoRecon/src/autorecon/autorecon.py /usr/local/bin/autorecon
        fi
    }
fi

# Amass
echo "[*] Installing Amass..."
if ! command -v amass &> /dev/null; then
    go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null && \
    sudo cp ~/go/bin/amass /usr/local/bin/ 2>/dev/null || \
    echo "WARNING: Amass installation failed"
fi

# Nuclei
echo "[*] Installing Nuclei..."
if ! command -v nuclei &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
    sudo cp ~/go/bin/nuclei /usr/local/bin/ 2>/dev/null || \
    echo "WARNING: Nuclei installation failed"
fi

# TheHarvester
echo "[*] Installing TheHarvester..."
if [ ! -d /opt/theHarvester ]; then
    sudo git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
    cd /opt/theHarvester
    sudo pip3 install -r requirements.txt --break-system-packages
    cd -
    sudo ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theharvester
fi

# Responder
echo "[*] Installing Responder..."
if [ ! -d /opt/Responder ]; then
    sudo git clone https://github.com/lgandx/Responder.git /opt/Responder
    sudo chmod +x /opt/Responder/Responder.py
    sudo ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
fi

# enum4linux-ng
echo "[*] Installing enum4linux-ng..."
if [ ! -d /opt/enum4linux-ng ]; then
    sudo git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
    sudo pip3 install -r /opt/enum4linux-ng/requirements.txt --break-system-packages
    sudo chmod +x /opt/enum4linux-ng/enum4linux-ng.py
    sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
fi

# NetExec (formerly CrackMapExec)
echo "[*] Installing NetExec..."
if ! command -v netexec &> /dev/null && ! command -v nxc &> /dev/null; then
    sudo apt install -y pipx || true
    pipx install git+https://github.com/Pennyw0rth/NetExec --force 2>/dev/null || \
    sudo pip3 install git+https://github.com/Pennyw0rth/NetExec --break-system-packages || \
    echo "WARNING: NetExec installation failed, continuing..."
fi

# Subfinder
echo "[*] Installing Subfinder..."
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
    sudo cp ~/go/bin/subfinder /usr/local/bin/ 2>/dev/null || \
    echo "WARNING: Subfinder installation failed"
fi

# Rustscan
echo "[*] Installing Rustscan..."
if ! command -v rustscan &> /dev/null; then
    sudo apt install -y rustscan 2>/dev/null || \
    sudo snap install rustscan 2>/dev/null || \
    echo "WARNING: Rustscan installation failed (try: snap install rustscan)"
fi

# ===========================
# WEB APPLICATION SECURITY
# ===========================
echo ""
echo "[*] Installing Web Application Security Tools..."
sudo apt install -y gobuster nikto sqlmap

# ffuf
echo "[*] Installing ffuf..."
sudo apt install -y ffuf || {
    wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(uname -s)_$(uname -m | sed 's/x86_64/amd64/').tar.gz -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/
    sudo mv /tmp/ffuf /usr/local/bin/
    rm /tmp/ffuf.tar.gz
}

# WPScan
echo "[*] Installing WPScan..."
sudo apt install -y ruby ruby-dev
sudo gem install wpscan

# wafw00f
echo "[*] Installing wafw00f..."
sudo pip3 install wafw00f --break-system-packages

# testssl.sh
echo "[*] Installing testssl.sh..."
if [ ! -d /opt/testssl.sh ]; then
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl
fi

# httpx
echo "[*] Installing httpx..."
if ! command -v httpx &> /dev/null; then
    wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(uname -s)_$(uname -m | sed 's/x86_64/amd64/').zip -O /tmp/httpx.zip
    unzip -q /tmp/httpx.zip -d /tmp/
    sudo mv /tmp/httpx /usr/local/bin/
    rm /tmp/httpx.zip
fi

# jwt-tool
echo "[*] Installing jwt-tool..."
if [ ! -d /opt/jwt_tool ]; then
    sudo git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool
    sudo pip3 install pycryptodomex --break-system-packages
    sudo chmod +x /opt/jwt_tool/jwt_tool.py
    sudo ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
fi

# anew
echo "[*] Installing anew..."
if ! command -v anew &> /dev/null; then
    go install github.com/tomnomnom/anew@latest
    if [ -f ~/go/bin/anew ]; then
        sudo cp ~/go/bin/anew /usr/local/bin/
    else
        echo "WARNING: anew installation failed"
    fi
fi

# Feroxbuster
echo "[*] Installing feroxbuster..."
if ! command -v feroxbuster &> /dev/null; then
    wget -q https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -O /tmp/feroxbuster.zip
    unzip -q /tmp/feroxbuster.zip -d /tmp/
    sudo mv /tmp/feroxbuster /usr/local/bin/
    chmod +x /usr/local/bin/feroxbuster
    rm /tmp/feroxbuster.zip
fi

# Hakrawler
echo "[*] Installing hakrawler..."
if ! command -v hakrawler &> /dev/null; then
    go install github.com/hakluke/hakrawler@latest
    if [ -f ~/go/bin/hakrawler ]; then
        sudo cp ~/go/bin/hakrawler /usr/local/bin/
    else
        echo "WARNING: hakrawler installation failed"
    fi
fi

# Burp Suite Community Edition
echo "[*] Burp Suite Community Edition - Please download manually from https://portswigger.net/burp/communitydownload"

# ===========================
# AUTHENTICATION & PASSWORD
# ===========================
echo ""
echo "[*] Installing Authentication & Password Tools..."
sudo apt install -y hydra john hashcat hashid

# evil-winrm
echo "[*] Installing evil-winrm..."
sudo gem install evil-winrm

# ===========================
# BINARY ANALYSIS & REVERSE ENGINEERING
# ===========================
echo ""
echo "[*] Installing Binary Analysis & Reverse Engineering Tools..."
sudo apt install -y gdb binwalk checksec upx

# Volatility3
echo "[*] Installing Volatility3..."
if ! command -v vol &> /dev/null && ! command -v volatility3 &> /dev/null; then
    sudo pip3 install volatility3 --break-system-packages || \
    {
        if [ ! -d /opt/volatility3 ]; then
            sudo git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
            cd /opt/volatility3
            sudo pip3 install -r requirements.txt --break-system-packages
            cd -
            sudo ln -sf /opt/volatility3/vol.py /usr/local/bin/vol
        fi
    }
fi

# strings, objdump, readelf, xxd (from binutils and vim-common)
sudo apt install -y binutils vim-common

# Ghidra
echo "[*] Installing Ghidra..."
if ! command -v ghidra &> /dev/null; then
    sudo apt install -y default-jdk
    echo "Note: Ghidra requires manual download from https://ghidra-sre.org/"
    echo "      After download, extract to /opt/ghidra and add to PATH"
fi

# ropgadget
echo "[*] Installing ROPgadget..."
sudo pip3 install ropgadget --break-system-packages

# one-gadget
echo "[*] Installing one_gadget..."
sudo gem install one_gadget

# pwninit
echo "[*] Installing pwninit..."
if ! command -v pwninit &> /dev/null; then
    wget -q https://github.com/io12/pwninit/releases/latest/download/pwninit -O /tmp/pwninit
    chmod +x /tmp/pwninit
    sudo mv /tmp/pwninit /usr/local/bin/
fi

# ===========================
# METASPLOIT FRAMEWORK
# ===========================
echo ""
echo "[*] Installing Metasploit Framework..."
if ! command -v msfconsole &> /dev/null; then
    # Download script to temp location
    curl -o /tmp/msfinstall https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb
    # Verify download succeeded
    if [ -f /tmp/msfinstall ] && [ -s /tmp/msfinstall ]; then
        chmod 755 /tmp/msfinstall
        sudo /tmp/msfinstall
        rm -f /tmp/msfinstall
    else
        echo "WARNING: Metasploit download failed, skipping..."
    fi
fi

# Searchsploit (Exploit-DB)
echo "[*] Installing Searchsploit..."
if ! command -v searchsploit &> /dev/null; then
    sudo apt install -y exploitdb 2>/dev/null || \
    {
        if [ ! -d /opt/exploitdb ]; then
            sudo git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
            sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
            sudo /opt/exploitdb/searchsploit -u
        fi
    }
fi

# ===========================
# DIGITAL FORENSICS
# ===========================
echo ""
echo "[*] Installing Digital Forensics Tools..."
sudo apt install -y foremost testdisk steghide exiftool scalpel sleuthkit

# PhotoRec is part of testdisk package, no separate install needed

# Stegsolve (Java-based)
echo "[*] Installing Stegsolve..."
if [ ! -f /opt/stegsolve.jar ]; then
    sudo wget -q https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar -O /opt/stegsolve.jar
    echo '#!/bin/bash' | sudo tee /usr/local/bin/stegsolve
    echo 'java -jar /opt/stegsolve.jar "$@"' | sudo tee -a /usr/local/bin/stegsolve
    sudo chmod +x /usr/local/bin/stegsolve
fi

# zsteg
echo "[*] Installing zsteg..."
sudo gem install zsteg

# bulk-extractor
echo "[*] Installing bulk-extractor..."
if ! command -v bulk_extractor &> /dev/null; then
    sudo apt install -y bulk-extractor 2>/dev/null || \
    echo "WARNING: bulk-extractor not available in repositories, skipping..."
fi

# ===========================
# OSINT & INTELLIGENCE
# ===========================
echo ""
echo "[*] Installing OSINT & Intelligence Tools..."

# Sherlock
echo "[*] Installing Sherlock..."
if [ ! -d /opt/sherlock ]; then
    sudo git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock
    cd /opt/sherlock
    sudo pip3 install -r requirements.txt --break-system-packages
    sudo ln -sf /opt/sherlock/sherlock/sherlock.py /usr/local/bin/sherlock
    cd -
fi

# recon-ng
echo "[*] Installing recon-ng..."
if ! command -v recon-ng &> /dev/null; then
    if [ ! -d /opt/recon-ng ]; then
        sudo git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng
        cd /opt/recon-ng
        sudo pip3 install -r REQUIREMENTS --break-system-packages
        cd -
        sudo ln -sf /opt/recon-ng/recon-ng /usr/local/bin/recon-ng
    fi
fi

# SpiderFoot
echo "[*] Installing SpiderFoot..."
if [ ! -d /opt/spiderfoot ]; then
    sudo git clone https://github.com/smicallef/spiderfoot.git /opt/spiderfoot
    cd /opt/spiderfoot
    sudo pip3 install -r requirements.txt --break-system-packages
    cd -
fi

# TruffleHog
echo "[*] Installing TruffleHog..."
sudo pip3 install truffleHog --break-system-packages

# ===========================
# CLOUD SECURITY
# ===========================
echo ""
echo "[*] Installing Cloud Security Tools..."

# Trivy
echo "[*] Installing Trivy..."
if ! command -v trivy &> /dev/null; then
    sudo mkdir -p /etc/apt/keyrings
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /etc/apt/keyrings/trivy.gpg
    echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
    sudo apt update
    sudo apt install -y trivy
fi

# Prowler
echo "[*] Installing Prowler..."
sudo pip3 install prowler --break-system-packages 2>/dev/null || \
sudo pip3 install prowler --break-system-packages --ignore-installed typing_extensions || \
echo "WARNING: Prowler installation failed, continuing..."

# Docker Bench Security
echo "[*] Installing Docker Bench Security..."
if [ ! -d /opt/docker-bench-security ]; then
    sudo git clone https://github.com/docker/docker-bench-security.git /opt/docker-bench-security
fi

# AWS CLI
echo "[*] Installing AWS CLI..."
if ! command -v aws &> /dev/null; then
    sudo pip3 install awscli --break-system-packages 2>/dev/null || \
    {
        cd /tmp
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" 2>/dev/null
        unzip -q awscliv2.zip 2>/dev/null
        sudo ./aws/install 2>/dev/null || echo "WARNING: AWS CLI installation failed"
        rm -rf aws awscliv2.zip
        cd -
    }
fi

# Azure CLI
echo "[*] Installing Azure CLI..."
if ! command -v az &> /dev/null; then
    sudo mkdir -p /etc/apt/keyrings
    curl -sLS https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/azure-cli.list
    sudo apt update && sudo apt install -y azure-cli || echo "Azure CLI installation failed, continuing..."
fi

# Google Cloud SDK
echo "[*] Installing Google Cloud SDK..."
if ! command -v gcloud &> /dev/null; then
    sudo mkdir -p /usr/share/keyrings
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
    sudo apt update && sudo apt install -y google-cloud-sdk
fi

# kubectl
echo "[*] Installing kubectl..."
sudo apt install -y kubectl || {
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/
}

# ===========================
# NICHE/BONUS TOOLS
# ===========================
echo ""
echo "[*] Installing Niche/Bonus Tools..."

# waybackurls
echo "[*] Installing waybackurls..."
if ! command -v waybackurls &> /dev/null; then
    go install github.com/tomnomnom/waybackurls@latest
    if [ -f ~/go/bin/waybackurls ]; then
        sudo cp ~/go/bin/waybackurls /usr/local/bin/
    else
        echo "WARNING: waybackurls installation failed"
    fi
fi

# gau (GetAllUrls)
echo "[*] Installing gau..."
if ! command -v gau &> /dev/null; then
    go install github.com/lc/gau/v2/cmd/gau@latest
    if [ -f ~/go/bin/gau ]; then
        sudo cp ~/go/bin/gau /usr/local/bin/
    else
        echo "WARNING: gau installation failed"
    fi
fi

# arjun
echo "[*] Installing arjun..."
sudo pip3 install arjun --break-system-packages

# commix
echo "[*] Installing commix..."
if [ ! -d /opt/commix ]; then
    sudo git clone https://github.com/commixproject/commix.git /opt/commix
    sudo ln -sf /opt/commix/commix.py /usr/local/bin/commix
fi

# nosqlmap
echo "[*] Installing nosqlmap..."
if [ ! -d /opt/nosqlmap ]; then
    sudo git clone https://github.com/codingo/NoSQLMap.git /opt/nosqlmap
    cd /opt/nosqlmap
    sudo pip3 install -r requirements.txt --break-system-packages
    cd -
    sudo ln -sf /opt/nosqlmap/nosqlmap.py /usr/local/bin/nosqlmap
fi

# radare2
echo "[*] Installing radare2..."
sudo apt install -y radare2

# shodan CLI
echo "[*] Installing shodan CLI..."
sudo pip3 install shodan --break-system-packages

# paramspider
echo "[*] Installing paramspider..."
if [ ! -d /opt/paramspider ]; then
    sudo git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider
    cd /opt/paramspider
    sudo pip3 install -r requirements.txt --break-system-packages
    cd -
fi

# dalfox
echo "[*] Installing dalfox..."
if ! command -v dalfox &> /dev/null; then
    go install github.com/hahwul/dalfox/v2@latest
    if [ -f ~/go/bin/dalfox ]; then
        sudo cp ~/go/bin/dalfox /usr/local/bin/
    else
        echo "WARNING: dalfox installation failed"
    fi
fi

# sublist3r
echo "[*] Installing Sublist3r..."
if [ ! -d /opt/Sublist3r ]; then
    sudo git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
    cd /opt/Sublist3r
    sudo pip3 install -r requirements.txt --break-system-packages
    cd -
    sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
fi

# ===========================
# COPY GO TOOLS TO SYSTEM PATH
# ===========================
echo ""
echo "[*] Copying Go tools from ~/go/bin to /usr/local/bin..."
if [ -d ~/go/bin ]; then
    for tool in ~/go/bin/*; do
        if [ -f "$tool" ]; then
            toolname=$(basename "$tool")
            if ! command -v "$toolname" &> /dev/null; then
                sudo cp "$tool" /usr/local/bin/
                echo "  ✓ Copied $toolname"
            fi
        fi
    done
fi

echo ""
echo "=================================================="
echo "Security Tools Installation Complete!"
echo "=================================================="
echo ""
echo "Installed tools summary:"
echo "  ✓ Network & Recon: nmap, masscan, autorecon, amass, nuclei, etc."
echo "  ✓ Web App: gobuster, ffuf, nikto, sqlmap, wpscan, httpx, etc."
echo "  ✓ Auth/Password: hydra, john, hashcat, evil-winrm"
echo "  ✓ Binary/RE: ghidra, gdb, binwalk, ropgadget, one-gadget, etc."
echo "  ✓ Metasploit: msfvenom included"
echo "  ✓ Forensics: foremost, steghide, volatility3, exiftool, etc."
echo "  ✓ OSINT: sherlock, recon-ng, spiderfoot, trufflehog"
echo "  ✓ Cloud: trivy, prowler, aws-cli, azure-cli, gcloud, kubectl"
echo "  ✓ Niche: waybackurls, gau, arjun, commix, nosqlmap, etc."
echo ""
echo "Next step:"
echo "  Run ./setup_hexstrike_venv.sh to set up Hexstrike Python environment"
echo ""
