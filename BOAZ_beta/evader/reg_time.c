/* 
Reg Key time stomping. 

In contrast to file time stomping, registry key time stomping is a bit more complex. 
$Standard_Information and $FILE_NAME attributes are for file time modification. 
For registry key time modification, we need to use the $KEY_NAME attribute.

Usage:
.\timestomp_reg.exe "\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Run" "2020-01-01 12:34:56"
*/


#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001A)
#endif


#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Fix missing MinGW definitions
#ifndef _KEY_INFORMATION_CLASS
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;
#endif

typedef NTSTATUS (NTAPI *NtOpenKey_t)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtSetInformationKey_t)(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);

typedef NTSTATUS (NTAPI *NtQueryKey_t)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *NtEnumerateKey_t)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *NtFlushKey_t)(HANDLE KeyHandle);
typedef VOID (NTAPI *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
RtlInitUnicodeString_t RtlInitUnicodeShit = NULL;

typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION;

// Function declaration before use
void PrintLastWriteTime(HANDLE hKey, NtQueryKey_t NtQueryKey);

void ConvertSystemTimeToLargeInteger(const char *timestamp, LARGE_INTEGER *liTime) {
    SYSTEMTIME st;
    FILETIME ft;

    sscanf(timestamp, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu",
           &st.wYear, &st.wMonth, &st.wDay,
           &st.wHour, &st.wMinute, &st.wSecond);

    if (!SystemTimeToFileTime(&st, &ft)) {
        printf("[-] Error: SystemTimeToFileTime failed.\n");
        liTime->QuadPart = 0; // Ensure failure doesn't set an invalid value
        return;
    }

    // Convert FILETIME to LARGE_INTEGER format
    liTime->LowPart = ft.dwLowDateTime;
    liTime->HighPart = ft.dwHighDateTime;
}


void PrintLastWriteTime(HANDLE hKey, NtQueryKey_t NtQueryKey) {
    BYTE buffer[1024]; // Ensure buffer is large enough
    KEY_BASIC_INFORMATION *kbi = (KEY_BASIC_INFORMATION *)buffer;
    ULONG resultLength;

    NTSTATUS status = NtQueryKey(hKey, KeyBasicInformation, kbi, sizeof(buffer), &resultLength);

    if (status == 0) {
        FILETIME ft;
        SYSTEMTIME st;
        ft.dwLowDateTime = kbi->LastWriteTime.LowPart;
        ft.dwHighDateTime = kbi->LastWriteTime.HighPart;
        FileTimeToSystemTime(&ft, &st);
        printf("[+] Current Last Write Time: %04d-%02d-%02d %02d:%02d:%02d\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    } else {
        printf("[-] Failed to retrieve Last Write Time. Status: 0x%lX\n", (unsigned long)status);
    }
}


ULONG subkeyIndex = 0;
void ModifyRegistryRecursively(
    HANDLE hKey, 
    NtQueryKey_t NtQueryKey, 
    NtSetInformationKey_t NtSetInformationKey, 
    NtEnumerateKey_t NtEnumerateKey, 
    NtOpenKey_t NtOpenKey, 
    NtFlushKey_t NtFlushKey, 
    RtlInitUnicodeString_t RtlInitUnicodeShit, 
    const char *timestamp
);


void PrintTimeZoneOffset() {
    TIME_ZONE_INFORMATION tzInfo;
    DWORD status = GetTimeZoneInformation(&tzInfo);

    int utcOffset = -tzInfo.Bias / 60; // Convert bias from minutes to hours

    if (status == TIME_ZONE_ID_STANDARD) {
        printf("[!] Your local time is currently UTC%+d (Standard Time adjustment applied).\n", utcOffset);
    } else if (status == TIME_ZONE_ID_DAYLIGHT) {
        int dstOffset = utcOffset - (tzInfo.DaylightBias / 60);
        printf("[!] Your local time is currently UTC%+d (Daylight Saving Time active).\n", dstOffset);
    } else {
        printf("[!] Your local time is currently UTC%+d (No timezone data available).\n", utcOffset);
    }
}



int main(int argc, char *argv[]) {



    printf("[*] Registry Key Time St0m9ing tool\n");
    printf("[*] verison 0.8 \n");
    printf("[*] By: Thomas X Meng. \n");

    if (argc < 2) {
        printf("[*] Usage: %s <RegistryPath> [YYYY-MM-DD HH:MM:SS] [-s]\n", argv[0]);
        return 1;
    }

    BOOL recursive = (argc == 4 && strcmp(argv[3], "-s") == 0);
    BOOL query_only = (argc == 2);

    PrintTimeZoneOffset();


    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (!hNtDll) {
        printf("[-] Failed to load ntdll.dll\n");
        return 1;
    }

    NtOpenKey_t NtOpenKey = (NtOpenKey_t)GetProcAddress(hNtDll, "NtOpenKey");
    NtSetInformationKey_t NtSetInformationKey = (NtSetInformationKey_t)GetProcAddress(hNtDll, "NtSetInformationKey");
    NtFlushKey_t NtFlushKey = (NtFlushKey_t)GetProcAddress(hNtDll, "NtFlushKey");
    NtQueryKey_t NtQueryKey = (NtQueryKey_t)GetProcAddress(hNtDll, "NtQueryKey");
    NtEnumerateKey_t NtEnumerateKey = (NtEnumerateKey_t)GetProcAddress(hNtDll, "NtEnumerateKey");
    RtlInitUnicodeShit = (RtlInitUnicodeString_t)GetProcAddress(hNtDll, "RtlInitUnicodeString");

    if (!NtOpenKey || !NtSetInformationKey || !NtFlushKey || !NtQueryKey || !NtEnumerateKey || !RtlInitUnicodeShit) {
        printf("[-] Failed to load necessary functions from ntdll.dll\n");
        FreeLibrary(hNtDll);
        return 1;
    }

    UNICODE_STRING ustrKeyPath;
    OBJECT_ATTRIBUTES objAttrs;
    HANDLE hKey;
    wchar_t regPath[512];

    swprintf(regPath, 512, L"%hs", argv[1]);
    RtlInitUnicodeShit(&ustrKeyPath, regPath);
    InitializeObjectAttributes(&objAttrs, &ustrKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NtOpenKey(&hKey, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &objAttrs) != 0) {
        printf("[-] Failed to open registry key: %s\n", argv[1]);
        FreeLibrary(hNtDll);
        return 1;
    }

    // Query Mode (if no timestamp is given)
    if (query_only) {
        printf("[*] Querying Last Write Time for: %s\n", argv[1]);
        PrintLastWriteTime(hKey, NtQueryKey);
        CloseHandle(hKey);
        FreeLibrary(hNtDll);
        return 0;
    }

    // Recursive Mode (-s switch)
    if (recursive) {
        subkeyIndex = 0;
        printf("[*] Recursively modifying timestamps under: %s\n", argv[1]);
        ModifyRegistryRecursively(hKey, NtQueryKey, NtSetInformationKey, NtEnumerateKey, NtOpenKey, NtFlushKey, RtlInitUnicodeShit, argv[2]);
        CloseHandle(hKey);
        FreeLibrary(hNtDll);
        return 0;
    }


    // Single key timestamp modification: 
    // Print the original timestamp
    printf("[*] Original timestamp:\n");
    PrintLastWriteTime(hKey, NtQueryKey);

    LARGE_INTEGER liTime;
    ConvertSystemTimeToLargeInteger(argv[2], &liTime);

    KEY_WRITE_TIME_INFORMATION keyWriteTime;
    keyWriteTime.LastWriteTime = liTime;

    if (NtSetInformationKey(hKey, KeyWriteTimeInformation, &keyWriteTime, sizeof(KEY_WRITE_TIME_INFORMATION)) != 0) {
        printf("[-] NtSetInformationKey failed.\n");
    } else {
        printf("[+] Successfully modified registry key Last Write time.\n");
    }

    NtFlushKey(hKey); // Ensures modification is written to disk
    printf("[*] Modified timestamp:\n");
    PrintLastWriteTime(hKey, NtQueryKey); // Print the modified timestamp

    CloseHandle(hKey);
    FreeLibrary(hNtDll);
    return 0;
}




void ModifyRegistryRecursively(
    HANDLE hKey, 
    NtQueryKey_t NtQueryKey, 
    NtSetInformationKey_t NtSetInformationKey, 
    NtEnumerateKey_t NtEnumerateKey, 
    NtOpenKey_t NtOpenKey, 
    NtFlushKey_t NtFlushKey, 
    RtlInitUnicodeString_t RtlInitUnicodeShit, 
    const char *timestamp
) {
    
    ULONG resultLength;
    BYTE buffer[1024];  // Increased buffer size for key enumeration
    KEY_BASIC_INFORMATION *keyInfo = (KEY_BASIC_INFORMATION *)buffer;

    while (TRUE) {
        NTSTATUS status = NtEnumerateKey(hKey, subkeyIndex, KeyBasicInformation, keyInfo, sizeof(buffer), &resultLength);
        
        if (status == STATUS_NO_MORE_ENTRIES) {
            printf("[*] No more subkeys at index %lu\n", subkeyIndex);
            break;
        } else if (status != 0) {
            printf("[-] NtEnumerateKey failed at index %lu, Status: 0x%lX\n", subkeyIndex, (unsigned long)status);
            break;
        }

        // Copy subkey name and ensure NULL termination
        wchar_t subKeyName[256];
        wcsncpy(subKeyName, keyInfo->Name, keyInfo->NameLength / sizeof(WCHAR));
        subKeyName[keyInfo->NameLength / sizeof(WCHAR)] = L'\0';

        printf("\n[*] Processing Subkey: %ls\n", subKeyName);

        UNICODE_STRING subKeyUstr;
        OBJECT_ATTRIBUTES subKeyAttrs;
        HANDLE hSubKey;

        RtlInitUnicodeShit(&subKeyUstr, subKeyName);
        InitializeObjectAttributes(&subKeyAttrs, &subKeyUstr, OBJ_CASE_INSENSITIVE, hKey, NULL);

        if (NtOpenKey(&hSubKey, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE, &subKeyAttrs) != 0) {
            printf("[-] Failed to open subkey: %ls\n", subKeyName);
            subkeyIndex++;
            continue;
        }

        // Print original timestamp
        printf("[*] Original timestamp for subkey: %ls\n", subKeyName);
        PrintLastWriteTime(hSubKey, NtQueryKey);

        // Modify timestamp
        LARGE_INTEGER liTime;
        ConvertSystemTimeToLargeInteger(timestamp, &liTime);
        KEY_WRITE_TIME_INFORMATION keyWriteTime;
        keyWriteTime.LastWriteTime = liTime;

        if (NtSetInformationKey(hSubKey, KeyWriteTimeInformation, &keyWriteTime, sizeof(KEY_WRITE_TIME_INFORMATION)) != 0) {
            printf("[-] Failed to modify timestamp for subkey: %ls\n", subKeyName);
        } else {
            printf("[+] Successfully modified timestamp for subkey: %ls\n", subKeyName);
        }

        NtFlushKey(hSubKey);

        // Print modified timestamp
        printf("[*] Modified timestamp for subkey: %ls\n", subKeyName);
        PrintLastWriteTime(hSubKey, NtQueryKey);

        // Recursive call for subkeys
        ModifyRegistryRecursively(hSubKey, NtQueryKey, NtSetInformationKey, NtEnumerateKey, NtOpenKey, NtFlushKey, RtlInitUnicodeShit, timestamp);

        CloseHandle(hSubKey);
        subkeyIndex++;  // Move to the next subkey
    }
}

