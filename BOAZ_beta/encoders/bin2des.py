# #!/usr/bin/env python3
# import sys
# import subprocess

# BLOCK_SIZE = 8

# def build_des_key_classic_7to8(raw_key_7: bytes) -> bytes:
#     """
#     Convert 7 bytes -> 8 bytes with DES parity bits (LSB approach).
#     Same function matching Windows SystemFunction001.

#     [DEBUG ADDED] - prints the final 8-byte key in hex
#     """
#     if len(raw_key_7) != 7:
#         raise ValueError("7-byte key required for Windows DES")

#     inbits = 0
#     for b in raw_key_7:
#         inbits = (inbits << 8) | b

#     out_bytes = bytearray(8)
#     shift = 56 - 7
#     for i in range(8):
#         block_7 = (inbits >> shift) & 0x7F
#         shift -= 7
#         bit_count = bin(block_7).count('1')
#         if bit_count % 2 == 0:
#             # Even -> set LSB = 1
#             block_8 = (block_7 << 1) | 0x01
#         else:
#             # Odd -> set LSB = 0
#             block_8 = (block_7 << 1)
#         out_bytes[i] = block_8 & 0xFF

#     final_8 = bytes(out_bytes)
#     print(f"[DEBUG] build_des_key_classic_7to8(): final 8-byte key = {final_8.hex()}")

#     return final_8

# def pkcs7_pad(plaintext: bytes, block_size=8) -> bytes:
#     """
#     PKCS7 pad so the length is a multiple of 8.
#     Same as your C code's pad_data().

#     [DEBUG ADDED] - prints original len and padded len
#     """
#     original_len = len(plaintext)
#     pad_len = block_size - (len(plaintext) % block_size)
#     padded_data = plaintext + bytes([pad_len]) * pad_len
#     print(f"[DEBUG] pkcs7_pad(): original_len={original_len}, pad_len={pad_len}, new_len={len(padded_data)}")
#     return padded_data

# def encrypt_des_ecb_singleblock(plaintext_8: bytes, raw_key_7: bytes) -> bytes:
#     """
#     Encrypt exactly 8 bytes with an 8-byte DES key (via OpenSSL -nopad).
#     Mirrors a single SystemFunction001 call.

#     [DEBUG ADDED] - prints block data and key
#     """
#     if len(plaintext_8) != 8:
#         raise ValueError("Must be exactly 8 bytes for single-block DES")
#     if len(raw_key_7) != 7:
#         raise ValueError("SystemFunction001 expects a 7-byte key")

#     print(f"[DEBUG] encrypt_des_ecb_singleblock(): block to encrypt = {plaintext_8.hex()}")

#     final_key_8 = build_des_key_classic_7to8(raw_key_7)
#     key_hex = final_key_8.hex()

#     cmd = [
#         "openssl", "enc", "-des-ecb", "-nosalt", "-nopad",
#         "-K", key_hex,
#         "-iv", "0000000000000000"
#     ]
#     print(f"[DEBUG] OpenSSL cmd: {cmd}")

#     proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     stdout, stderr = proc.communicate(plaintext_8)

#     print(f"[DEBUG] OpenSSL return code: {proc.returncode}")
#     if stderr:
#         print(f"[DEBUG] OpenSSL stderr: {stderr.decode(errors='replace')}")

#     if proc.returncode != 0:
#         raise RuntimeError(f"OpenSSL DES error: {stderr.decode(errors='replace')}")
#     print(f"[DEBUG] Single-block ciphertext = {stdout.hex()}")
#     return stdout

# def encrypt_des_ecb_pkcs7_multiblock(plaintext: bytes, raw_key_7: bytes) -> bytes:
#     """
#     EXACTLY replicates Windows approach:
#     1) PKCS7 pad
#     2) Split into 8-byte blocks
#     3) For each block, call single-block encryption

#     [DEBUG ADDED] - prints block index, etc.
#     """
#     padded = pkcs7_pad(plaintext, BLOCK_SIZE)
#     ciphertext = b""
#     total_blocks = len(padded) // BLOCK_SIZE
#     print(f"[DEBUG] encrypt_des_ecb_pkcs7_multiblock(): total_blocks={total_blocks}")

#     for i in range(0, len(padded), BLOCK_SIZE):
#         block_index = i // BLOCK_SIZE
#         block = padded[i:i+BLOCK_SIZE]
#         print(f"[DEBUG] encrypting block #{block_index}, offset={i}, data={block.hex()}")
#         enc_block = encrypt_des_ecb_singleblock(block, raw_key_7)
#         ciphertext += enc_block

#     return ciphertext

# def print_c_arrays(key_7: bytes, ciphertext: bytes):
#     """
#     Print the key and ciphertext in C array form, like your AES example.
#     E.g.:
#       unsigned char DESkey[] = { 0x42, 0x4f, ... };
#       unsigned char magiccode[] = { 0x0a, 0x78, ... };

#     [DEBUG] - prints final array sizes
#     """
#     print(f"[DEBUG] print_c_arrays(): key_7_len={len(key_7)}, ciphertext_len={len(ciphertext)}")

#     # DESkey array (the raw 7-byte key)
#     print("unsigned char DESkey[] = { " +
#           ", ".join(f"0x{x:02x}" for x in key_7) + " };")
#     # magiccode array (the final encrypted data)
#     print("unsigned char magiccode[] = { " +
#           ", ".join(f"0x{x:02x}" for x in ciphertext) + " };")

# def main():
#     # Hardcoded 7-byte DES key
#     raw_key_7 = b"BOAZIST"
#     print(f"[DEBUG] main(): Using raw_key_7={raw_key_7.hex()}")

#     # Usage: python3 bin2des.py <input_file>
#     if len(sys.argv) != 2:
#         print(f"Usage: {sys.argv[0]} <payload_file>")
#         sys.exit(1)

#     input_file = sys.argv[1]
#     try:
#         with open(input_file, "rb") as f:
#             content = f.read()
#             print(f"[DEBUG] main(): read {len(content)} bytes from {input_file}")
#     except FileNotFoundError:
#         print(f"Error: File '{input_file}' not found.")
#         sys.exit(1)

#     # Encrypt the entire file's contents in multi-block DES-ECB with PKCS7
#     print("[DEBUG] main(): starting encrypt_des_ecb_pkcs7_multiblock()")
#     ciphertext = encrypt_des_ecb_pkcs7_multiblock(content, raw_key_7)
#     print("[DEBUG] main(): encryption complete")

#     # Print C arrays: DESkey[] and magiccode[]
#     print_c_arrays(raw_key_7, ciphertext)

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
import sys
import subprocess

BLOCK_SIZE = 8

def build_des_key_classic_7to8(raw_key_7: bytes) -> bytes:
    """Convert 7-byte Windows key to 8-byte DES key (with parity bits)."""
    if len(raw_key_7) != 7:
        raise ValueError("7-byte key required for Windows DES")

    inbits = 0
    for b in raw_key_7:
        inbits = (inbits << 8) | b

    out_bytes = bytearray(8)
    shift = 56 - 7
    for i in range(8):
        block_7 = (inbits >> shift) & 0x7F
        shift -= 7
        bit_count = bin(block_7).count('1')
        block_8 = (block_7 << 1) | (0x01 if bit_count % 2 == 0 else 0x00)
        out_bytes[i] = block_8 & 0xFF

    final_key_8 = bytes(out_bytes)
    # print(f"[DEBUG] build_des_key_classic_7to8(): final 8-byte key = {final_key_8.hex()}")
    return final_key_8

def pkcs7_pad(plaintext: bytes, block_size=8) -> bytes:
    """PKCS#7 pad plaintext to be a multiple of 8 bytes."""
    original_len = len(plaintext)
    pad_len = block_size - (len(plaintext) % block_size)
    padded_data = plaintext + bytes([pad_len]) * pad_len
    # print(f"[DEBUG] pkcs7_pad(): original_len={original_len}, pad_len={pad_len}, new_len={len(padded_data)}")
    return padded_data

def encrypt_des_ecb_bulk(plaintext: bytes, raw_key_7: bytes) -> bytes:
    """Encrypt all blocks at once using OpenSSL for better performance."""
    final_key_8 = build_des_key_classic_7to8(raw_key_7)
    key_hex = final_key_8.hex()

    # print(f"[DEBUG] encrypt_des_ecb_bulk(): Encrypting {len(plaintext)} bytes in one call to OpenSSL")
    
    cmd = [
        "openssl", "enc", "-des-ecb", "-nosalt", "-nopad",
        "-K", key_hex, "-iv", "0000000000000000"
    ]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(plaintext)

    if proc.returncode != 0:
        # print(f"[DEBUG] OpenSSL ERROR: {stderr.decode(errors='replace')}")
        raise RuntimeError(f"OpenSSL DES encryption failed.")

    return stdout

def print_c_arrays(key_7: bytes, ciphertext: bytes):
    """Prints DES key and ciphertext in C array format."""
    # print("[DEBUG] print_c_arrays(): Generating C-style output")
    
    # Print DES Key
    print("unsigned char DESkey[] = { " + ", ".join(f"0x{x:02x}" for x in key_7) + " };")
    
    # Print Ciphertext
    print("unsigned char magic_code[] = { " + ", ".join(f"0x{x:02x}" for x in ciphertext) + " };")

def main():
    raw_key_7 = b"BOAZIST"
    # print(f"[DEBUG] main(): Using raw_key_7={raw_key_7.hex()}")

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payload_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    try:
        with open(input_file, "rb") as f:
            content = f.read()
            # print(f"[DEBUG] main(): read {len(content)} bytes from {input_file}")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    # print("[DEBUG] main(): Applying PKCS7 padding")
    padded_content = pkcs7_pad(content, BLOCK_SIZE)

    # print("[DEBUG] main(): Encrypting file in bulk")
    ciphertext = encrypt_des_ecb_bulk(padded_content, raw_key_7)

    # print("[DEBUG] main(): Encryption complete")
    print_c_arrays(raw_key_7, ciphertext)

if __name__ == "__main__":
    main()
