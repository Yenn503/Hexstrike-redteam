#!/usr/bin/env python3

#### RC4 encryption that is identical to that of SystemFunction032

import sys
import os
from typing import Iterator

def key_scheduling(key: bytes) -> list[int]:
    sched = [i for i in range(256)]
    i = 0
    for j in range(256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        sched[j], sched[i] = sched[i], sched[j]
    return sched

def stream_generation(sched: list[int]) -> Iterator[int]:
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (sched[i] + j) % 256
        sched[i], sched[j] = sched[j], sched[i]
        yield sched[(sched[i] + sched[j]) % 256]

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    return bytes(char ^ next(key_stream) for char in plaintext)

def format_c_array(name: str, data: bytes) -> str:
    hex_bytes = ''.join(f"\\x{b:02x}" for b in data)
    formatted_lines = [hex_bytes[i:i + 64] for i in range(0, len(hex_bytes), 64)]
    return f'unsigned char {name}[] = \n"' + '"\n"'.join(formatted_lines) + '";'

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    # Generate a random 32-byte RC4 key
    # rc4_key = os.urandom(32)
    rc4_key = b'BoazIsTheBestaaa'  # Add two underscores to make it 16 bytes


    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = encrypt(plaintext, rc4_key)

    # # Decrypt (RC4 is symmetric, so encrypting again should decrypt)
    # decrypted = encrypt(ciphertext, rc4_key)

    # # Compare results
    # if decrypted == plaintext:
    #     print("[+] Python RC4 encryption and decryption WORK!")
    # else:
    #     print("[-] Python RC4 decryption FAILED! Data is corrupted.")

    # # Output first and last 10 bytes of decrypted data
    # print(f"Decrypted (first 10 bytes): {decrypted[:10]}")
    # print(f"Decrypted (last 10 bytes): {decrypted[-10:]}")

    # Print formatted C arrays
    print(format_c_array("rc4_key", rc4_key))
    print(format_c_array("magiccode", ciphertext))
