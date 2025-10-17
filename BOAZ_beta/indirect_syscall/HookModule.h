#pragma once

#define OPCODE_SUB_RSP 0xec8348
#define OPCODE_RET_CC 0xccc3
#define OPCODE_RET 0xc3
#define OPCODE_CALL 0xe8
#define OPCODE_JMP 0xe9
#define OPCODE_JMP_LEN 8
#define MAX_SEARCH_LIMIT 20
#define CALL_FIRST 1
#define RESUME_FLAG 0x10000
#define TRACE_FLAG 0x100
#define OPCODE_SYSCALL 0x050F
#define OPCODE_SZ_DIV 4
#define OPCODE_SZ_ACC_VIO 2
//#define OPCODE_SYSCALL_OFF 0x12
//#define OPCODE_SYSCALL_RET_OFF 0x14
#define FIFTH_ARGUMENT 0x8*0x5
#define SIXTH_ARGUMENT 0x8*0x6
#define SEVENTH_ARGUMENT 0x8*0x7
#define EIGHTH_ARGUMENT 0x8*0x8
#define NINTH_ARGUMENT 0x8*0x9
#define TENTH_ARGUMENT 0x8*0xa
#define ELEVENTH_ARGUMENT 0x8*0xb
#define TWELVETH_ARGUMENT 0x8*0xc

#define TRIGGER_INT_DIV_EXCEPTION int a = 2; int b = 0; int c = a / b;
#define TRIGGER_ACCESS_VIOLOATION_EXCEPTION int *a = 0; int b = *a;

/// Some definitions for Vectored Exception Handling, they can be moved to seperate header files in folder evaders.
typedef enum _MYPROCESSINFOCLASS
{
    myProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    myProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    myProcessIoCounters, // q: IO_COUNTERS
    myProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    myProcessTimes, // q: KERNEL_USER_TIMES
    myProcessBasePriority, // s: KPRIORITY
    myProcessRaisePriority, // s: ULONG
    myProcessDebugPort, // q: HANDLE
    myProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    myProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    myProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    myProcessLdtSize, // s: PROCESS_LDT_SIZE
    myProcessDefaultHardErrorMode, // qs: ULONG
    myProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    myProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    myProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    myProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    myProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    myProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    myProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    myProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    myProcessAffinityMask, // s: KAFFINITY
    myProcessPriorityBoost, // qs: ULONG
    myProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    myProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    myProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    myProcessWow64Information, // q: ULONG_PTR
    myProcessImageFileName, // q: UNICODE_STRING
    myProcessLUIDDeviceMapsEnabled, // q: ULONG
    myProcessBreakOnTermination, // qs: ULONG
    myProcessDebugObjectHandle, // q: HANDLE // 30
    myProcessDebugFlags, // qs: ULONG
    myProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    myProcessIoPriority, // qs: IO_PRIORITY_HINT
    myProcessExecuteFlags, // qs: ULONG
    myProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement 
    myProcessCookie, // q: ULONG
    myProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    myProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    myProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    myProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    myProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    myProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    myProcessImageFileNameWin32, // q: UNICODE_STRING
    myProcessImageFileMapping, // q: HANDLE (input)
    myProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    myProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    myProcessGroupInformation, // q: USHORT[]
    myProcessTokenVirtualizationEnabled, // s: ULONG
    myProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    myProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    myProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    myProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    myProcessDynamicFunctionTableInformation,
    myProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    myProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    myProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    myProcessHandleTable, // q: ULONG[] // since WINBLUE
    myProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    myProcessCommandLineInformation, // q: UNICODE_STRING // 60
    myProcessProtectionInformation, // q: PS_PROTECTION
    myProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    myProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    myProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    myProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    myProcessDefaultCpuSetsInformation,
    myProcessAllowedCpuSetsInformation,
    myProcessSubsystemProcess,
    myProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    myProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    myProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    myProcessIumChallengeResponse,
    myProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    myProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    myProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    myProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    myProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    myProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    myProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    myProcessDisableSystemAllowedCpuSets, // 80
    myProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    myProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    myProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    myProcessCaptureTrustletLiveDump,
    myProcessTelemetryCoverage,
    myProcessEnclaveInformation,
    myProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    myProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    myProcessImageSection, // q: HANDLE
    myProcessDebugAuthInformation, // since REDSTONE4 // 90
    myProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    myProcessSequenceNumber, // q: ULONGLONG
    myProcessLoaderDetour, // since REDSTONE5
    myProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    myProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    myProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    myProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    myProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    myProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    myProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    myProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    myProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    myProcessCreateStateChange, // since WIN11
    myProcessApplyStateChange,
    myProcessEnableOptionalXStateFeatures,
    myMaxProcessInfoClass
} MYPROCESSINFOCLASS;

#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];


// typedef struct _UNICODE_STRING
// {
//     USHORT Length;
//     USHORT MaximumLength;
//     PWSTR Buffer;
// } UNICODE_STRING, * PUNICODE_STRING;
// typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA2
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    UCHAR ShutdownInProgress;
    PVOID ShutdownThreadId;
#endif
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;



	typedef struct _UNICODE_STRING2
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING2, * PUNICODE_STRING2;
	typedef const UNICODE_STRING2* PCUNICODE_STRING2;

	typedef struct _CURDIR2
	{
		UNICODE_STRING2 DosPath;
		HANDLE Handle;
	} CURDIR2, * PCURDIR2;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

	typedef struct _RTL_DRIVE_LETTER_CURDIR2
	{
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		UNICODE_STRING2 DosPath;
	} RTL_DRIVE_LETTER_CURDIR2, * PRTL_DRIVE_LETTER_CURDIR2;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

	typedef struct _RTL_USER_PROCESS_PARAMETERS2
	{
		ULONG MaximumLength;
		ULONG Length;

		ULONG Flags;
		ULONG DebugFlags;

		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;

		CURDIR2 CurrentDirectory;
		UNICODE_STRING2 DllPath;
		UNICODE_STRING2 ImagePathName;
		UNICODE_STRING2 CommandLine;
		PWCHAR Environment;

		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;

		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING2 WindowTitle;
		UNICODE_STRING2 DesktopInfo;
		UNICODE_STRING2 ShellInfo;
		UNICODE_STRING2 RuntimeData;
		RTL_DRIVE_LETTER_CURDIR2 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;
	} RTL_USER_PROCESS_PARAMETERS2, * PRTL_USER_PROCESS_PARAMETERS2;


typedef struct _PEB2
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        } s1;
    } u1;

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA2 Ldr;
    PRTL_USER_PROCESS_PARAMETERS2 ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; 
            ULONG ReservedBits0 : 24;
			// ULONG ProcessInJob : 1;
			// ULONG ProcessInitializing : 1;
			// ULONG ProcessUsingVEH : 1;
			// ULONG ProcessUsingVCH : 1;
			// ULONG ProcessUsingFTH : 1;
			// ULONG ProcessPreviouslyThrottled : 1;
			// ULONG ProcessCurrentlyThrottled : 1;
			// ULONG ReservedBits0 : 25;
        } s2;
    } u2;
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    } u3;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    
    PVOID ReadOnlySharedMemoryBase; 
    PVOID SharedData; // HotpatchInformation
    PVOID *ReadOnlyStaticServerData;
    
    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING2 CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA *LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB2, *PPEB2;

typedef NTSTATUS (__stdcall* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _DllInfo {
	ULONG64 DllBaseAddress;
	ULONG64 DllEndAddress;
} DllInfo;

void IntialiseHooks();
void DestroyHooks();
void SetHwBp(ULONG_PTR FuncAddress, int flag, int ssn);
int GetSsnByName(PCHAR syscall);
LPVOID ModifyHandlers(HANDLE hProcess, BOOL enable);
