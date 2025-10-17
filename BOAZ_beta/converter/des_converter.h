#ifndef DES_CONVERTER_H
#define DES_CONVERTER_H


#include <windows.h> 

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define BLOCK_SIZE 8  // DES block size


typedef NTSTATUS(WINAPI *SystemFunction002_t)(const BYTE *data, const BYTE *key, LPBYTE output);

// Global function pointers to advapi32
// SystemFunction001_t sysfunc01 = NULL;
extern SystemFunction002_t sysfunc02;

void remove_padding(unsigned char *data, size_t *length);

// Decrypt multi-block ciphertext with SystemFunction002 in 8-byte chunks
void decrypt_with_des(unsigned char *ciphertext, size_t *length,
                      const unsigned char *key, unsigned char *plaintext);

int des_magic(unsigned char *magiccode, size_t magic_len, unsigned char *magic_code);


#endif // DES_CONVERTER_H
