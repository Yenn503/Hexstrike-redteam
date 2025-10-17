"""
BOAZ Encoder Reference Data
Contains definitions for 12 encoding schemes
"""

ENCODING_REFERENCE = {
    "uuid": {
        "description": "Universally Unique Identifier format",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Low entropy, legitimate-looking format"
    },
    "xor": {
        "description": "Simple XOR encryption",
        "strength": "Low",
        "speed": "Very Fast",
        "use_case": "Quick obfuscation, testing"
    },
    "mac": {
        "description": "MAC address format encoding",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Network-themed obfuscation"
    },
    "ipv4": {
        "description": "IPv4 address format encoding",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Network-related obfuscation"
    },
    "base45": {
        "description": "Base45 encoding",
        "strength": "Low",
        "speed": "Fast",
        "use_case": "Alternative to Base64"
    },
    "base64": {
        "description": "Standard Base64 encoding",
        "strength": "Low",
        "speed": "Very Fast",
        "use_case": "Common encoding, may be flagged"
    },
    "base58": {
        "description": "Base58 encoding (Bitcoin-style)",
        "strength": "Low",
        "speed": "Fast",
        "use_case": "Alternative base encoding"
    },
    "aes": {
        "description": "AES encryption",
        "strength": "High",
        "speed": "Medium",
        "use_case": "Strong encryption, higher entropy"
    },
    "aes2": {
        "description": "AES with divide-and-conquer decryption",
        "strength": "High",
        "speed": "Medium",
        "use_case": "Bypass logical path hijacking"
    },
    "des": {
        "description": "DES encryption (SystemFunction002)",
        "strength": "Medium",
        "speed": "Medium",
        "use_case": "System API-based encryption"
    },
    "chacha": {
        "description": "ChaCha20 stream cipher",
        "strength": "High",
        "speed": "Fast",
        "use_case": "Modern encryption, less fingerprinted"
    },
    "rc4": {
        "description": "RC4 encryption (SystemFunction032/033)",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "System API-based encryption"
    }
}
