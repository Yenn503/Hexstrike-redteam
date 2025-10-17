#include "rc4_converter.h"

#include <windows.h>


/* set up entryption functions*/
/// Sys func 32 and 33: 
// Setup structs

// Define the function pointers
typedef NTSTATUS(WINAPI* SystemFunction032_t)(PCRYPT_BUFFER pData, PDATA_KEY pKey);
// typedef NTSTATUS(WINAPI* SystemFunction033_t)(PCRYPT_BUFFER pData, PDATA_KEY pKey);

SystemFunction032_t sysfunc32 = NULL;
// SystemFunction033_t SystemFunction033 = NULL;


static char _key[16] = { 'B', 'o', 'a', 'z', 'I', 's', 'T', 'h', 
                         'e', 'B', 'e', 's', 't', 'a', 'a', 'a' };


CRYPT_BUFFER pData = { 0 };
DATA_KEY pKey = { 0 };


void initialize_keys() {
    pKey.Buffer = (PVOID)(_key);
    pKey.Length = sizeof(_key);
    pKey.MaximumLength = sizeof(_key);
}

void initialize_data(unsigned char* dllEntryPoint1, DWORD dll_len) {
    pData.Buffer = (unsigned char*)(dllEntryPoint1);
    pData.Length = dll_len;
    pData.MaximumLength = dll_len;
}


// void initialize_keys() {

//     // Allocate memory for the key
//     pKey.Buffer = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//     if (!pKey.Buffer) {
//         printf("[-] Failed to allocate memory for key\n");
//         exit(1);
//     }

//     // Copy the key into allocated memory
//     memcpy(pKey.Buffer, raw_key, 16);

//     pKey.Length = pKey.MaximumLength = 16;
// }

// void initialize_data(unsigned char* encrypted_shellcode, DWORD shellcode_len) {
//     pData.Buffer = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//     if (!pData.Buffer) {
//         printf("[-] Failed to allocate memory for shellcode\n");
//         exit(1);
//     }

//     // Ensure memory is zeroed before copying data
//     memset(pData.Buffer, 0, shellcode_len);

//     // Copy encrypted shellcode into allocated memory
//     memcpy(pData.Buffer, encrypted_shellcode, shellcode_len);

//     pData.Length = pData.MaximumLength = shellcode_len;
// }

