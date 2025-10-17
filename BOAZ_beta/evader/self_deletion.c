/* 
Self-deletion technique using NTFS alternate data streams to mark it for post-execution detection
Perform() function can be called before your last exeuction step, placed jus tbefore that line of code
-d --self-deletion
*/

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tchar.h>
#include "self_deletion.h"

void perform() {
    // Define the stream name
    wchar_t stream[] = L":BOAZ";

    // Calculate the lengths
    int stream_length = wcslen(stream) * sizeof(wchar_t);
    DWORD length = sizeof(FILE_RENAME_INFO) + stream_length;

    // Allocate memory for FILE_RENAME_INFO structure
    FILE_RENAME_INFO *rename_info = (FILE_RENAME_INFO *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);

    if (rename_info == NULL) {
        wprintf(L"[-] HeapAlloc failed\n");
        return;
    }

    // Set the DeleteFile flag for FILE_DISPOSITION_INFO
    FILE_DISPOSITION_INFO delete_file;
    delete_file.DeleteFile = TRUE;

    // Set the file name length for rename_info
    rename_info->FileNameLength = stream_length - 2;

    // Copy the stream name into the FileName field
    memcpy(rename_info->FileName, stream, stream_length);

    // Get the full path of the current executable
    wchar_t full_path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, full_path, MAX_PATH)) {
        wprintf(L"[-] Failed to get the current executable path\n");
        HeapFree(GetProcessHeap(), 0, rename_info);
        return;
    }

    // Open the file with DELETE and SYNCHRONIZE access
    HANDLE h_file = CreateFileW(
        full_path,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (h_file == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to open file: %s\n", full_path);
        HeapFree(GetProcessHeap(), 0, rename_info);
        return;
    }

    // Rename the file to the stream
    if (!SetFileInformationByHandle(h_file, FileRenameInfo, rename_info, length)) {
        wprintf(L"[-] Failed to rename file\n");
        CloseHandle(h_file);
        HeapFree(GetProcessHeap(), 0, rename_info);
        return;
    }

    // Close the file handle
    CloseHandle(h_file);

    // Reopen the file with DELETE and SYNCHRONIZE access
    h_file = CreateFileW(
        full_path,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (h_file == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to reopen file: %s\n", full_path);
        HeapFree(GetProcessHeap(), 0, rename_info);
        return;
    }

    // Mark the file for deletion
    if (!SetFileInformationByHandle(h_file, FileDispositionInfo, &delete_file, sizeof(FILE_DISPOSITION_INFO))) {
        wprintf(L"[-] Failed to delete file\n");
        CloseHandle(h_file);
        HeapFree(GetProcessHeap(), 0, rename_info);
        return;
    }

    // Close the file handle again
    CloseHandle(h_file);

    // Free the allocated memory
    HeapFree(GetProcessHeap(), 0, rename_info);


    // NEW CODE: Delete the alternate data stream using DeleteFileW for wide characters
    if (DeleteFileW(full_path)) {
        wprintf(L"[+] Alternate data stream deleted successfully\n");
    } else {
        wprintf(L"[-] Failed to delete alternate data stream\n");
    }

    //sleep
    Sleep(1000);


    // wprintf(L"File renamed and marked for deletion successfully\n");
}

// int main() {
//     perform();
//     return 0;
// }
