# HexStrike RedTeam Framework 🔥

**Unified AI-Powered Red Team & Penetration Testing Framework with BOAZ Integration**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)
[![Tools](https://img.shields.io/badge/Security%20Tools-155%2B-brightgreen.svg)]()
[![BOAZ](https://img.shields.io/badge/BOAZ-77%2B%20Loaders-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

> **⚠️ AUTHORIZED USE ONLY**: This framework is designed for authorized security assessments, penetration testing, red team operations, and security research. Unauthorized access to computer systems is illegal.

---

## 🎯 What's New: BOAZ Red Team Integration

HexStrike RedTeam now includes **BOAZ**, the advanced payload evasion framework, providing:

- **✨ 77+ Process Injection Loaders**: Syscall, stealth, memory guard, threadless techniques
- **🔒 12 Encoding Schemes**: AES, ChaCha20, UUID, XOR, MAC, and more
- **🛡️ EDR/AV Evasion**: API unhooking, ETW patching, LLVM obfuscation
- **🔬 Binary Analysis**: Entropy analysis and optimization
- **⚡ One Unified MCP**: 155+ security tools in a single interface

---

## 🚀 Quick Start

###Prerequisites

```bash
# Python 3.8+
python3 --version

# Install dependencies
pip install -r requirements.txt
```

### Installation

```bash
# Clone the repository
git clone https://github.com/Yenn503/Hexstrike-redteam.git
cd Hexstrike-redteam

# Optional: Set BOAZ_PATH (defaults to ./BOAZ_beta)
export BOAZ_PATH=$(pwd)/BOAZ_beta
```

### Running the Framework

**Terminal 1: Start HexStrike Server**
```bash
python3 hexstrike_server.py
# Server starts on http://127.0.0.1:8888
```

**Terminal 2: Start MCP Client**
```bash
python3 hexstrike_mcp.py
# MCP server ready for AI agent connections
```

---

## 🛠️ Framework Capabilities

### HexStrike AI Core (150+ Tools)

| Category | Tools | Count |
|----------|-------|-------|
| **Network Scanning** | nmap, rustscan, masscan, zmap, amass, subfinder | 30+ |
| **Web Testing** | nuclei, gobuster, sqlmap, nikto, dalfox, ffuf | 40+ |
| **Cloud Security** | prowler, trivy, scout-suite, kube-hunter | 20+ |
| **Binary Analysis** | ghidra, radare2, gdb, pwntools, ropper | 25+ |
| **CTF & Forensics** | volatility, stegseek, hashcat, john | 20+ |
| **Bug Bounty** | Automated reconnaissance & vulnerability hunting | Workflows |

### BOAZ Red Team Module (NEW! 🔥)

| Category | Count | Description |
|----------|-------|-------------|
| **Syscall Loaders** | 11 | Direct syscalls, bypass userland hooks |
| **Stealth Loaders** | 17 | Advanced memory scan evasion |
| **Memory Guard** | 6 | Breakpoint handlers, ROP trampolines |
| **Threadless** | 6 | Module stomping, VT pointer injection |
| **VEH/VCH** | 5 | Exception handler-based injection |
| **Encoders** | 12 | UUID, AES, ChaCha20, XOR, MAC, RC4 |

---

## 🔥 BOAZ Usage Examples

### Example 1: Generate EDR-Evasive Payload

```python
# Maximum evasion for CrowdStrike/Defender bypass
boaz_generate_payload(
    input_file="beacon.exe",
    output_file="output/evasive_beacon.exe",
    loader=51,                  # Sifu Breakpoint Handler
    encoding="aes",             # AES encryption
    compiler="akira",           # LLVM obfuscation
    obfuscate=True,            # Source obfuscation
    obfuscate_api=True,        # API obfuscation
    anti_emulation=True,       # Sandbox evasion
    etw=True,                  # ETW patching
    api_unhooking=True,        # API unhooking
    entropy=2                  # Entropy reduction
)
```

### Example 2: Discover Available Loaders

```python
# List all stealth loaders
boaz_list_loaders(category="stealth")

# List all loaders
boaz_list_loaders(category="all")
```

### Example 3: Analyze Binary Entropy

```python
# Check if payload will trigger heuristics
boaz_analyze_binary(file_path="output/payload.exe")
# Returns entropy score (0-8) and recommendations
```

### Example 4: Validate Configuration

```python
# Validate before generating
boaz_validate_options(
    loader=51,
    encoding="aes",
    compiler="akira"
)
```

---

## 🎯 Complete Tool List

### BOAZ Red Team Tools (5)

1. **`boaz_generate_payload`**: Generate evasive payloads with 77+ loaders
2. **`boaz_list_loaders`**: Browse process injection techniques
3. **`boaz_list_encoders`**: View encoding/encryption schemes
4. **`boaz_analyze_binary`**: Analyze binary entropy
5. **`boaz_validate_options`**: Validate configuration

### HexStrike AI Tools (150+)

<details>
<summary><b>Network & Infrastructure (30+)</b></summary>

- nmap_scan, rustscan_scan, masscan_scan, zmap_scan
- amass_enum, subfinder_enum, assetfinder_scan
- httpx_probe, katana_crawl, gau_fetch, waybackurls
- dnsx_resolve, massdns_resolve, puredns_resolve
- naabu_scan, sx_scan, shodan_search, censys_search

</details>

<details>
<summary><b>Web Application Testing (40+)</b></summary>

- nuclei_scan, jaeles_scan, nikto_scan
- gobuster_scan, feroxbuster_scan, dirsearch_scan, ffuf_fuzz
- sqlmap_scan, ghauri_scan
- dalfox_xss, xsstrike_scan
- arjun_params, paramspider_discover, x8_discover
- wpscan, joomscan, droopescan
- commix_inject, tplmap_scan

</details>

<details>
<summary><b>Cloud Security (20+)</b></summary>

- prowler_scan, scout_suite_assessment, pacu_exploit
- kube_hunter_scan, kubeaudit_audit, kubebench_check
- trivy_scan, grype_scan, clair_scan, anchore_scan
- steampipe_query, cartography_map
- cloudsploit_scan, cs_suite_scan

</details>

<details>
<summary><b>Binary & Reverse Engineering (25+)</b></summary>

- ghidra_analyze, radare2_analyze, binary_ninja_analyze
- gdb_debug, windbg_debug, x64dbg_debug
- pwntools_exploit, ropper_gadgets, one_gadget_find
- capa_analyze, flare_analyze, yara_scan
- strings_extract, binwalk_extract, foremost_extract

</details>

<details>
<summary><b>CTF & Forensics (20+)</b></summary>

- volatility_analyze, rekall_analyze
- stegseek_crack, stegsolve_analyze, zsteg_detect
- hashcat_crack, john_crack, rsatool_attack
- wireshark_analyze, tshark_capture, zeek_analyze
- binwalk_extract, foremost_recover

</details>

<details>
<summary><b>Bug Bounty Workflows</b></summary>

- bugbounty_reconnaissance_workflow
- bugbounty_vulnerability_hunting
- bugbounty_comprehensive_assessment
- bugbounty_osint_gathering

</details>

---

## 🤖 AI-Driven Intelligence

### Specialized Agents

1. **IntelligentDecisionEngine**: AI tool selection & parameter optimization
2. **BugBountyWorkflowManager**: Automated bug bounty hunting
3. **CTFWorkflowManager**: CTF challenge solving (7 categories)
4. **CVEIntelligenceManager**: CVE tracking & exploit correlation
5. **BrowserAgent**: Headless browser automation
6. **AIExploitGenerator**: Automated exploit generation
7. **FailureRecoverySystem**: Intelligent error recovery
8. **ParameterOptimizer**: Context-aware parameter tuning
9. **TechnologyDetector**: Tech stack identification (60+ signatures)
10. **VulnerabilityCorrelator**: Attack chain discovery

### Error Recovery Features

- **Intelligent Retries**: Auto-recovery from failures
- **Alternative Tools**: Fallback tool suggestions
- **Parameter Adjustment**: Auto-tuning on errors
- **Human Escalation**: Complex failure handling

---

## 📁 Project Structure

```
hexstrike-redteam/
├── hexstrike_server.py          # Main API server (Flask)
├── hexstrike_mcp.py             # MCP client (FastMCP)
├── requirements.txt             # Python dependencies
│
├── boaz/                        # BOAZ Integration Module
│   ├── __init__.py
│   ├── boaz_manager.py         # Core BOAZ manager
│   ├── loader_reference.py     # 77 loader definitions
│   └── encoder_reference.py    # 12 encoder definitions
│
├── BOAZ_beta/                   # BOAZ Framework
│   ├── Boaz.py                 # Main BOAZ script
│   ├── loaders/                # Injection templates
│   ├── encoders/               # Encoding modules
│   ├── output/                 # Generated payloads
│   └── notepad.exe             # Test payload
│
└── assets/                      # Framework assets
```

---

## 🔒 Security & Ethics

### ✅ Authorized Use

- Penetration testing with written permission
- Bug bounty programs within scope
- CTF competitions and training
- Security research in controlled environments
- Red team assessments with authorization

### ❌ Prohibited Use

- Attacking systems without permission
- Unauthorized access or credential theft
- Malware distribution
- Violating computer fraud laws
- Any illegal activity

**Always obtain written authorization before testing!**

---

## 🧪 Testing the Integration

### Test BOAZ Module

```bash
# Test imports
python3 -c "from boaz import BOAZManager; print('✅ BOAZ OK')"

# Test server startup
python3 hexstrike_server.py --debug

# Generate test payload
cd BOAZ_beta
python3 Boaz.py -f notepad.exe -o output/test.exe -l 16 -e uuid
```

---

## 🙏 Credits

### HexStrike AI
- **Original Framework**: [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai)
- Enhanced with AI-driven intelligence and automation

### BOAZ Framework
- **Original Project**: [thomasxm/Boaz_beta](https://github.com/thomasxm/Boaz_beta)
- 77+ process injection loaders and evasion techniques

### Integration
- **Author**: [Yenn503](https://github.com/Yenn503)
- **Repository**: Unified red team framework with clean modular architecture
- **MCP Integration**: Single interface for AI-powered security testing

---

## 📊 Framework Statistics

- **Total Security Tools**: 155+
- **BOAZ Process Injection Loaders**: 77+
- **BOAZ Encoding Schemes**: 12
- **AI Agents**: 12+
- **Bug Bounty Workflows**: 7+
- **CTF Categories Supported**: 7
- **Cloud Platforms**: AWS, Azure, GCP, Kubernetes

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS PROGRAM.

**This framework is designed for authorized security professionals only. Unauthorized access to computer systems is illegal.**

---

## 🔗 Links

- **GitHub**: https://github.com/Yenn503/Hexstrike-redteam
- **Issues**: https://github.com/Yenn503/Hexstrike-redteam/issues
- **MCP Protocol**: https://modelcontextprotocol.io/
- **Original HexStrike**: https://github.com/0x4m4/hexstrike-ai
- **Original BOAZ**: https://github.com/thomasxm/Boaz_beta

---

**Built with ❤️ for the security community**

*Red Team | Bug Bounty | CTF | Security Research*
