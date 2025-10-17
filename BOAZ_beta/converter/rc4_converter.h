#ifndef RC4_CONVERTER_H
#define RC4_CONVERTER_H


#include <windows.h> 

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, *PCRYPT_BUFFER, DATA_KEY, *PDATA_KEY, CLEAR_DATA, *PCLEAR_DATA, CYPHER_DATA, *PCYPHER_DATA;

typedef NTSTATUS(WINAPI* SystemFunction032_t)(PCRYPT_BUFFER pData, PDATA_KEY pKey);
extern SystemFunction032_t sysfunc32;

extern CRYPT_BUFFER pData;
extern DATA_KEY pKey;

void initialize_data(unsigned char* dllEntryPoint1, DWORD dll_len);
void initialize_keys();


#endif // RC4_CONVERTER_H
