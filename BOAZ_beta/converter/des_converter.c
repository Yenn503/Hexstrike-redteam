/*
 SystemFunction001 -> Encrypt one 8-byte block at a time (DES)
 SystemFunction002 -> Decrypt one 8-byte block at a time (DES)
 We do PKCS7 padding to handle multi-block data.
 Expands your 7-byte key to 8 bytes with DES parity bits (internally in Win).
*/

#include "des_converter.h"


#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  // for calloc

// #define BLOCK_SIZE 8  // DES block size

// Windows internal prototypes
// typedef NTSTATUS(WINAPI *SystemFunction001_t)(const BYTE *data, const BYTE *key, LPBYTE output);
typedef NTSTATUS(WINAPI *SystemFunction002_t)(const BYTE *data, const BYTE *key, LPBYTE output);

// Global function pointers to advapi32
// SystemFunction001_t sysfunc01 = NULL;
SystemFunction002_t sysfunc02 = NULL;

/* 
   Because we're only DECRYPTING the pre-encrypted magiccode,
   we do NOT need pad_data() (encryption side).
   We only need remove_padding() after we call SystemFunction002.
*/

// PKCS7 remove
void remove_padding(unsigned char *data, size_t *length) {
    // The last byte is the padding length
    unsigned char pad_value = data[*length - 1];
    if (pad_value > 0 && pad_value <= BLOCK_SIZE) {
        *length -= pad_value;  // Remove those pad_value bytes
        data[*length] = '\0';  // Null-terminate
    }
}

// Decrypt multi-block ciphertext with SystemFunction002 in 8-byte chunks
void decrypt_with_des(unsigned char *ciphertext, size_t *length,
                      const unsigned char *key, unsigned char *plaintext)
{
    if (!sysfunc02) {
        printf("[-] Failed to load SystemFunction002\n");
        return;
    }

    // Decrypt each 8-byte block
    for (size_t i = 0; i < *length; i += BLOCK_SIZE) {
        NTSTATUS status = sysfunc02(&ciphertext[i], key, &plaintext[i]);
        if (status != STATUS_SUCCESS) {
            printf("[-] SystemFunction002 failed at block %zu\n", i / BLOCK_SIZE);
        }
    }

    // Now strip PKCS7 padding from the final plaintext
    remove_padding(plaintext, length);
}

int des_magic(unsigned char *magic_code, size_t magiccode_len, unsigned char *magiccode)
{
    // 1) Load advapi32 and resolve SystemFunctionXXX
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    if (!hAdvapi32) {
        printf("[-] Failed to load ADVAPI32.dll\n");
        return -1;
    }

    // sysfunc01 = (SystemFunction001_t)GetProcAddress(hAdvapi32, "SystemFunction001");
    sysfunc02 = (SystemFunction002_t)GetProcAddress(hAdvapi32, "SystemFunction002");

    if (!sysfunc02) {
        printf("[-] Failed to get SystemFunction001 or SystemFunction002\n");
        return -1;
    }

    // 2) Our 8-byte key. 
    //    Typically "BOAZIST" + '\0', so 7 bytes + 1 parity or 0x00 at end
    unsigned char key[8] = { 'B', 'O', 'A', 'Z', 'I', 'S', 'T', 0x00 };

    // 3) The pre-encrypted data (DES-ECB, PKCS7). Each block is 8 bytes.
    //    We'll decrypt it with SystemFunction002



    // 5) Allocate a buffer for plaintext (same size or bigger)
    // unsigned char *magiccode = (unsigned char *)calloc(magiccode_len + 1, 1);

    // 6) Decrypt
    printf("[+] Decrypting magiccode (len=%zu) with SystemFunction002...\n", magiccode_len);
    decrypt_with_des(magic_code, &magiccode_len, key, magiccode);

    // 7) Print final results
    printf("[+] magiccode length after remove_padding: %zu\n", magiccode_len);
    // printf("[+] Final magiccode data (ASCII): %s\n", magiccode);

    // Optionally, print magiccode in hex
    // printf("[+] Final magiccode data (hex): ");
    // for (size_t i = 0; i < magiccode_len; i++) {
    //     printf("%02X ", magiccode[i]);
    // }

    printf("[+] First 30 decrypted magic bytes: ");
    for (size_t i = 0; i < 30 && i < magiccode_len; i++) {
        printf("%02X ", magiccode[i]);
    }
    printf("\n");

    if (magiccode_len > 60) {  // Only print last 30 if data is big enough
        printf("[+] Last 30 decrypted magic bytes: ");
        for (size_t i = magiccode_len - 30; i < magiccode_len; i++) {
            printf("%02X ", magiccode[i]);
        }
        printf("\n");
    }


    return 1337;  


}
