#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <winternl.h>
#include "HookModule.h"


DllInfo NtdllInfo;
PCONTEXT SavedContext;
PVOID h1, h2;
PVOID b2, s9;
ULONG_PTR SyscallEntryAddr;
BOOL ExtendedArgs = FALSE;
int IsSubRsp = 0;
int SyscallNo = 0;
int OPCODE_SYSCALL_OFF = 0;
int OPCODE_SYSCALL_RET_OFF = 0;

void dummyfunction() {
    // TODO: add another dummy function that has a large stack size, and change dummy functions for each call. 
    MessageBoxA(NULL, "Hello, world!", "ANSI MessageBox", MB_OK | MB_ICONINFORMATION);
    // DefWindowProcA(NULL, WM_CLOSE, 0, 0);

}

LPVOID ModifyHandlers(HANDLE hProcess, BOOL enable);

void InitialiseDllInfo(DllInfo* obj, const char* DllName) {
    HMODULE hModuledll = GetModuleHandleA(DllName);

    MODULEINFO ModuleInfo;
    if (GetModuleInformation(GetCurrentProcess(), hModuledll, &ModuleInfo, sizeof(MODULEINFO)) == 0) {
        printf("[!] GetModuleInformation failed\n");
        return;
    }

    obj->DllBaseAddress = (ULONG64)ModuleInfo.lpBaseOfDll;
    obj->DllEndAddress = obj->DllBaseAddress + ModuleInfo.SizeOfImage;
}

LONG WINAPI AddHwBpVeh(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

        printf("\n[+] Inside VEH-1 Handler");
        // print the rip: 
        printf("[+] Exception Address: %p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

        if ( ExceptionInfo->ContextRecord->Dr0 || ExceptionInfo->ContextRecord->Dr1 || ExceptionInfo->ContextRecord->Dr2 || ExceptionInfo->ContextRecord->Dr3 || ExceptionInfo->ContextRecord->Dr6 || ExceptionInfo->ContextRecord->Dr7) {
            ExceptionInfo->ContextRecord = 0; // clear the context record
            // exit the program: 
            ExitProcess(0);
        } else {

            printf("[+] Inside access violation, no debugger present. We may continue. \n");
        }

        // SyscallEntryAddr = ExceptionInfo->ContextRecord->Rcx;

        // for (int i = 0; i < 25; i++) {
        //     // find syscall ret opcode offset
        //     if (*(BYTE*)(SyscallEntryAddr + i) == 0x0F && *(BYTE*)(SyscallEntryAddr + i + 1) == 0x05) {
        //         OPCODE_SYSCALL_OFF = i;
        //         OPCODE_SYSCALL_RET_OFF = i + 2;
        //         break;
        //     }
        // }

        // // Set hwbp at the syscall opcode
        // ExceptionInfo->ContextRecord->Dr0 = (SyscallEntryAddr);
        // ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 0);

        // // Set hwbp at the ret opcode
        // ExceptionInfo->ContextRecord->Dr1 = (SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF);
        // ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 2);

        // ExceptionInfo->ContextRecord->Rip += OPCODE_SZ_ACC_VIO;
        // printf("\n[*] Hardware Breakpoint added at address: %#llx (syscall)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr0);
        // printf("[*] Hardware Breakpoint added at address: %#llx (ret)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr1);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI AddHwBpVch(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

    
        printf("\n[+] Inside VCH-1 Handler");

        SyscallEntryAddr = ExceptionInfo->ContextRecord->Rcx;

        for (int i = 0; i < 25; i++) {
            // find syscall ret opcode offset
            if (*(BYTE*)(SyscallEntryAddr + i) == 0x0F && *(BYTE*)(SyscallEntryAddr + i + 1) == 0x05) {
                OPCODE_SYSCALL_OFF = i;
                OPCODE_SYSCALL_RET_OFF = i + 2;
                break;
            }
        }

        // Set hwbp at the syscall opcode
        ExceptionInfo->ContextRecord->Dr0 = (SyscallEntryAddr);
        ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 0);

        // Set hwbp at the ret opcode
        ExceptionInfo->ContextRecord->Dr1 = (SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF);
        ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 | (1 << 2);

        ExceptionInfo->ContextRecord->Rip += OPCODE_SZ_ACC_VIO;
        printf("\n[*] Hardware Breakpoint added at address: %#llx (syscall)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr0);
        printf("[*] Hardware Breakpoint added at address: %#llx (ret)\n", (ULONG_PTR)ExceptionInfo->ContextRecord->Dr1);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}



LONG WINAPI HandlerHwBpVeh(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        // // handler for syscall hwbp
        // if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr)) {
        //     printf("[+] Inside VEH-2 Handler\n");

        //     printf("[*] Hardware Breakpoint hit at %#llx (syscall)\n", ExceptionInfo->ContextRecord->Rip);
        //     printf("[*] Storing Context\n");

        //     // Clear hwbp
        //     ExceptionInfo->ContextRecord->Dr0 = 0;
        //     ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 0);


        //     // save the registers and clear hwbp
        //     // memcpy_s(SavedContext, sizeof CONTEXT, ExceptionInfo->ContextRecord, sizeof CONTEXT);
        //     memcpy(SavedContext, ExceptionInfo->ContextRecord, sizeof(CONTEXT));

        //     // change RIP to printf()
        //     ExceptionInfo->ContextRecord->Rip = (ULONG_PTR)dummyfunction;

        //     // Set the Trace Flag
        //     ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;

        //     return EXCEPTION_CONTINUE_EXECUTION;
        // }

        // // Handler for syscall ret opcode
        // else if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF)) {
        //     printf("[*] Hardware Breakpoint hit at %#llx (ret)\n", ExceptionInfo->ContextRecord->Rip);
        //     printf("[*] Restoring stack pointer\n\n");

        //     // Clear hwbp
        //     ExceptionInfo->ContextRecord->Dr1 = 0;
        //     ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 2);

        //     // change stack so that it can return back to our program
        //     ExceptionInfo->ContextRecord->Rsp = SavedContext->Rsp;

        //     return EXCEPTION_CONTINUE_EXECUTION;
        // }

        // // Handler for the Trace flag
        // else if (ExceptionInfo->ContextRecord->Rip >= NtdllInfo.DllBaseAddress &&
        //     ExceptionInfo->ContextRecord->Rip <= NtdllInfo.DllEndAddress) {

        //     // Find sub rsp, x where x is greater than what you want
        //     if (IsSubRsp == 0) {
        //         for (int i = 0; i < 80; i++) {
        //             if (*(UINT16*)(ExceptionInfo->ContextRecord->Rip + i) == OPCODE_RET_CC) break;

        //             if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) & 0xffffff) == OPCODE_SUB_RSP) {
        //                 if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) >> 24) >= 0x58) {

        //                     // appropriate stack frame found
        //                     IsSubRsp = 1;
        //                     ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
        //                     return EXCEPTION_CONTINUE_EXECUTION;
        //                 }
        //                 else break;
        //             }
        //         }
        //     }

        //     // wait for a call to take place
        //     if (IsSubRsp == 1) {
        //         // function frame does not contain call instruction
        //         if (*(UINT16*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET_CC || *(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET)
        //             IsSubRsp = 0;
        //         // function proceds to perform a call operation
        //         else if (*(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_CALL) {
        //             IsSubRsp = 2;
        //             ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
        //             return EXCEPTION_CONTINUE_EXECUTION;
        //         }
        //     }

        //     // appropriate stack frame and function frame found
        //     if (IsSubRsp == 2) {
        //         IsSubRsp = 0;
        //         printf("[*] Inside ntdll after setting TF at %#llx (%#llx)\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rip - NtdllInfo.DllBaseAddress);
        //         printf("[*] Generating stack & changing RIP & invoking intended syscall (ssn: %#x)\n", SyscallNo);

        //         ULONG64 TempRsp = ExceptionInfo->ContextRecord->Rsp;
        //         memcpy(ExceptionInfo->ContextRecord, SavedContext, sizeof(CONTEXT));

        //         ExceptionInfo->ContextRecord->Rsp = TempRsp;

        //         // emulate syscall
        //         // mov r10, rcx
        //         ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
        //         // mov rax, #ssn
        //         ExceptionInfo->ContextRecord->Rax = SyscallNo;
        //         // set RIP to syscall opcode
        //         ExceptionInfo->ContextRecord->Rip = SyscallEntryAddr + OPCODE_SYSCALL_OFF;

        //         // if >4 agrs
        //         if (ExtendedArgs) {
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + FIFTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + FIFTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SIXTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SIXTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SEVENTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + EIGHTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + EIGHTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + NINTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + NINTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TENTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + ELEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + ELEVENTH_ARGUMENT);
        //             *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TWELVETH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TWELVETH_ARGUMENT);
        //         }


        //         // Clear Trace Flag
        //         ExceptionInfo->ContextRecord->EFlags &= ~TRACE_FLAG;

        //         return EXCEPTION_CONTINUE_EXECUTION;
        //     }
        // }

        // continue tracing
        ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}



LONG WINAPI HandlerHwBpVch(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // handler for syscall hwbp
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr)) {
            
            printf("\n[+] Inside VCH-2 Handler");
            printf("[*] Hardware Breakpoint hit at %#llx (syscall)\n", ExceptionInfo->ContextRecord->Rip);
            printf("[*] Storing Context\n");

            // Clear hwbp
            ExceptionInfo->ContextRecord->Dr0 = 0;
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 0);


            // save the registers and clear hwbp
            // memcpy_s(SavedContext, sizeof CONTEXT, ExceptionInfo->ContextRecord, sizeof CONTEXT);
            memcpy(SavedContext, ExceptionInfo->ContextRecord, sizeof(CONTEXT));

            // change RIP to printf()
            ExceptionInfo->ContextRecord->Rip = (ULONG_PTR)dummyfunction;

            // Set the Trace Flag
            ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Handler for syscall ret opcode
        else if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)(SyscallEntryAddr + OPCODE_SYSCALL_RET_OFF)) {

            printf("\n[+] Inside VCH-2 Handler");
            printf("[*] Hardware Breakpoint hit at %#llx (ret)\n", ExceptionInfo->ContextRecord->Rip);
            printf("[*] Restoring stack pointer\n\n");

            // Clear hwbp
            ExceptionInfo->ContextRecord->Dr1 = 0;
            ExceptionInfo->ContextRecord->Dr7 = ExceptionInfo->ContextRecord->Dr7 & ~(1 << 2);

            // change stack so that it can return back to our program
            ExceptionInfo->ContextRecord->Rsp = SavedContext->Rsp;

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        // Handler for the Trace flag
        else if (ExceptionInfo->ContextRecord->Rip >= NtdllInfo.DllBaseAddress &&
            ExceptionInfo->ContextRecord->Rip <= NtdllInfo.DllEndAddress) {

            // Find sub rsp, x where x is greater than what you want
            if (IsSubRsp == 0) {
                for (int i = 0; i < 80; i++) {
                    if (*(UINT16*)(ExceptionInfo->ContextRecord->Rip + i) == OPCODE_RET_CC) break;

                    if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) & 0xffffff) == OPCODE_SUB_RSP) {
                        if ((*(UINT32*)(ExceptionInfo->ContextRecord->Rip + i) >> 24) >= 0x58) {

                            // appropriate stack frame found
                            IsSubRsp = 1;
                            ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                        else break;
                    }
                }
            }

            // wait for a call to take place
            if (IsSubRsp == 1) {
                // function frame does not contain call instruction
                if (*(UINT16*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET_CC || *(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_RET)
                    IsSubRsp = 0;
                // function proceds to perform a call operation
                else if (*(BYTE*)ExceptionInfo->ContextRecord->Rip == OPCODE_CALL) {
                    IsSubRsp = 2;
                    ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // appropriate stack frame and function frame found
            if (IsSubRsp == 2) {
                IsSubRsp = 0;
                printf("[*] Inside ntdll after setting TF at %#llx (%#llx)\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rip - NtdllInfo.DllBaseAddress);
                printf("[*] Generating stack & changing RIP & invoking intended syscall (ssn: %#x)\n", SyscallNo);

                ULONG64 TempRsp = ExceptionInfo->ContextRecord->Rsp;
                memcpy(ExceptionInfo->ContextRecord, SavedContext, sizeof(CONTEXT));

                ExceptionInfo->ContextRecord->Rsp = TempRsp;

                // emulate syscall
                // mov r10, rcx
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                // mov rax, #ssn
                ExceptionInfo->ContextRecord->Rax = SyscallNo;
                // set RIP to syscall opcode
                ExceptionInfo->ContextRecord->Rip = SyscallEntryAddr + OPCODE_SYSCALL_OFF;

                // if >4 agrs
                if (ExtendedArgs) {
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + FIFTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + FIFTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SIXTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SIXTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + SEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + SEVENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + EIGHTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + EIGHTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + NINTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + NINTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + ELEVENTH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + ELEVENTH_ARGUMENT);
                    *(ULONG64*)(ExceptionInfo->ContextRecord->Rsp + TWELVETH_ARGUMENT) = *(ULONG64*)(SavedContext->Rsp + TWELVETH_ARGUMENT);
                }


                // Clear Trace Flag
                ExceptionInfo->ContextRecord->EFlags &= ~TRACE_FLAG;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // continue tracing
        ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


// TODO: Add a VCH instead of VEH to avoid detection. 


void IntialiseHooks() {
    h1 = AddVectoredExceptionHandler(CALL_FIRST, AddHwBpVeh);
    b2 = AddVectoredContinueHandler(CALL_FIRST, AddHwBpVch);
    h2 = AddVectoredExceptionHandler(CALL_FIRST, HandlerHwBpVeh);
    s9 = AddVectoredExceptionHandler(CALL_FIRST, HandlerHwBpVch);
    //  TODO: add VCH
    SavedContext = (PCONTEXT)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTEXT)));
    InitialiseDllInfo(&NtdllInfo, "ntdll.dll");

    printf("[*] Ntdll Start Address: %#llx\n", NtdllInfo.DllBaseAddress);
    printf("[*] Ntdll End Address: %#llx\n\n", NtdllInfo.DllEndAddress);
}

void DestroyHooks() {

    if (h1 != NULL)    RemoveVectoredExceptionHandler(h1);
    if (h2 != NULL)    RemoveVectoredExceptionHandler(h2);
    if (b2 != NULL)    RemoveVectoredContinueHandler(b2);
    if (s9 != NULL)    RemoveVectoredExceptionHandler(s9);

    // TODO: manually remove VEH and VCH from CrossProcessFlag to avoid forensic traces.
    LPVOID imageBaseAddress = ModifyHandlers(GetCurrentProcess(), FALSE);
    if (imageBaseAddress == NULL) {
        printf("[-] Failed to disable VEH and VCH in desginated process\n");
    } else {
        printf("[+] Succseefully disable VEH and VCH in desginated process\n");
        getchar();
    }

}

// TODO: use page guard to trigger exception, it is safer. 
void _SetHwBp(ULONG_PTR FuncAddress) {
    TRIGGER_ACCESS_VIOLOATION_EXCEPTION
}

void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn) {
    ExtendedArgs = flag;
    SyscallNo = ssn;
    _SetHwBp(FuncAddress);
}


int GetSsnByName(PCHAR syscall) {
    auto Ldr = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    auto Head = (PLIST_ENTRY)&Ldr->Reserved2[1];
    auto Next = Head->Flink;

    while (Next != Head) {
        auto ent = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
        Next = Next->Flink;
        auto m = (PBYTE)ent->DllBase;
        auto nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) continue; // no export table? skip

        auto exp = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
        if (!exp->NumberOfNames) continue;   // no symbols? skip

        auto dll = (PDWORD)(m + exp->Name);
        // // not ntdll.dll? skip
        // if ((dll[0] | 0x20202020) != 'ldtn') continue;
        // if ((dll[1] | 0x20202020) != 'ld.l') continue;
        // if ((*(USHORT*)&dll[2] | 0x0020) != '\x00l') continue;

        // Match first 4 bytes: 'n' 't' 'd' 'l' (in little endian -> 0x6C64746E)
        if ((dll[0] | 0x20202020) != 0x6C64746E) continue;
        // Match next 4 bytes: 'l' '.' 'd' 'l' => 0x6C642E6C
        if ((dll[1] | 0x20202020) != 0x6C642E6C) continue;
        // Match final 2 bytes: 'l' '\0' => 0x006C (little-endian)
        if (((*(USHORT*)&dll[2]) | 0x0020) != 0x006C) continue;

        // Load the Exception Directory.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (!rva) return -1;
        auto rtf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(m + rva);

        // Load the Export Address Table.
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto adr = (PDWORD)(m + exp->AddressOfFunctions);
        auto sym = (PDWORD)(m + exp->AddressOfNames);
        auto ord = (PWORD)(m + exp->AddressOfNameOrdinals);

        int ssn = 0;

        // Search runtime function table.
        for (int i = 0; rtf[i].BeginAddress; i++) {
            // Search export address table.
            for (int j = 0; j < exp->NumberOfFunctions; j++) {
                // begin address rva?
                if (adr[ord[j]] == rtf[i].BeginAddress) {
                    auto api = (PCHAR)(m + sym[j]);
                    auto s1 = api;
                    auto s2 = syscall;

                    // our system call? if true, return ssn
                    while (*s1 && (*s1 == *s2)) s1++, s2++;
                    int cmp = (int)*(PBYTE)s1 - *(PBYTE)s2;
                    if (!cmp) return ssn;

                    // if this is a syscall, increase the ssn value.
                    if (*(USHORT*)api == 0x775A) ssn++; // 'w' = 0x77, 'Z' = 0x5A
                }
            }
        }
    }
    return -1; // didn't find it.
}


//Enable the ProcessUsingVEH and VCH bit in the CrossProcessFlags member of the designated process PEB
//Returns the ImageBaseAddress if successful
LPVOID ModifyHandlers(HANDLE hProcess, BOOL enable) {
	//Get the base address of the PEB in the designated process
	PROCESS_BASIC_INFORMATION processInfo = { 0 };
	DWORD returnLength = 0;

    NtQueryInformationProcess_t MyNtQueryInformationProcess = 
        (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");


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
        printf("[+] Enabled VEH and VCH by modify the CrossProcessFlags in the designated process!\n");
        printf("[+] Designated Process ID: %d\n", GetProcessId(hProcess));
        return peb_copy.ImageBaseAddress;
    } else if (!enable && !(peb_copy.u2.CrossProcessFlags & 0xc)) {
        printf("[+] Disabled VEH and VCH by modify the CrossProcessFlags in the designated process!\n");
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