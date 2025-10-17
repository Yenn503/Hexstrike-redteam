"""
BOAZ Loader Reference Data
Contains definitions for 77+ process injection loaders
"""

LOADER_REFERENCE = {
    1: {
        "name": "Proxy Syscall + Custom Call Stack",
        "category": "syscall",
        "description": "Custom call stack with indirect syscall and threadless execution"
    },
    2: {
        "name": "APC Test Alert",
        "category": "syscall",
        "description": "APC-based testing mechanism"
    },
    3: {
        "name": "Sifu Syscall",
        "category": "syscall",
        "description": "Direct syscall implementation"
    },
    4: {
        "name": "UUID Manual Injection",
        "category": "syscall",
        "description": "Manual injection with UUID-encoded payload",
        "encoding_required": "uuid"
    },
    5: {
        "name": "Remote MockingJay",
        "category": "syscall",
        "description": "Remote process injection technique"
    },
    6: {
        "name": "Local Thread Hijacking",
        "category": "syscall",
        "description": "Hijacks existing thread for execution"
    },
    7: {
        "name": "Function Pointer Invoke",
        "category": "syscall",
        "description": "Local injection via function pointer"
    },
    8: {
        "name": "Ninja Syscall 2",
        "category": "syscall",
        "description": "Advanced syscall variant"
    },
    9: {
        "name": "RW Local MockingJay",
        "category": "syscall",
        "description": "Read-write MockingJay technique"
    },
    10: {
        "name": "Ninja Syscall 1",
        "category": "syscall",
        "description": "Ninja syscall implementation"
    },
    11: {
        "name": "Sifu Divide and Conquer",
        "category": "syscall",
        "description": "Syscall with divided execution",
        "encoding_required": "aes2"
    },
    14: {
        "name": "Exit Without Execution",
        "category": "userland",
        "description": "Testing loader that exits without execution"
    },
    15: {
        "name": "SysWhispers2 Classic",
        "category": "userland",
        "description": "Classic native API calls via SysWhispers2"
    },
    16: {
        "name": "Classic Userland APIs",
        "category": "userland",
        "description": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
    },
    17: {
        "name": "Sifu Syscall Divide & Conquer",
        "category": "syscall",
        "description": "Advanced Sifu syscall with divided execution"
    },
    18: {
        "name": "WriteProcessMemoryAPC",
        "category": "userland",
        "description": "Userland API with APC write method"
    },
    19: {
        "name": "DLL Overloading",
        "category": "stealth",
        "description": "DLL overloading technique"
    },
    20: {
        "name": "Stealth Injection (APC + DLL)",
        "category": "stealth",
        "description": "WriteProcessMemoryAPC with DLL overloading"
    },
    22: {
        "name": "Advanced Custom Call Stack",
        "category": "stealth",
        "description": "Indirect syscall with VEH->VCH and handler cleanup"
    },
    24: {
        "name": "Classic Native API",
        "category": "userland",
        "description": "Standard native API calls"
    },
    26: {
        "name": "Stealth Injection Advanced",
        "category": "stealth",
        "description": "3 APC variants + DLL overloading + dynamic API hashing"
    },
    27: {
        "name": "Stealth + Halo's Gate",
        "category": "stealth",
        "description": "Advanced injection with Halo's Gate patching"
    },
    28: {
        "name": "Halo's Gate + Custom Write",
        "category": "stealth",
        "description": "Halo's Gate with MAC/UUID write + invisible loading"
    },
    29: {
        "name": "Classic Indirect Syscall",
        "category": "syscall",
        "description": "Indirect syscall implementation"
    },
    30: {
        "name": "Classic Direct Syscall",
        "category": "syscall",
        "description": "Direct syscall implementation"
    },
    31: {
        "name": "MAC Address Injection",
        "category": "stealth",
        "description": "Payload encoded as MAC addresses",
        "encoding_required": "mac"
    },
    32: {
        "name": "Stealth Advanced",
        "category": "stealth",
        "description": "Advanced stealth injection"
    },
    33: {
        "name": "Indirect Syscall + Halo + Custom Stack",
        "category": "stealth",
        "description": "Combined stealth techniques"
    },
    34: {
        "name": "EDR Syscall No.1",
        "category": "stealth",
        "description": "EDR syscall with Halo's Gate and custom stack"
    },
    36: {
        "name": "EDR Syscall No.2",
        "category": "stealth",
        "description": "Alternative EDR syscall implementation"
    },
    37: {
        "name": "Stealth Memory Scan Evasion",
        "category": "stealth",
        "description": "Advanced loader with memory scan evasion"
    },
    38: {
        "name": "Phantom DLL Overloading",
        "category": "stealth",
        "description": "APC write with phantom DLL execution"
    },
    39: {
        "name": "Custom Stack PI Remote",
        "category": "stealth",
        "description": "Remote PI with threadless execution"
    },
    40: {
        "name": "Threadless DLL Notification",
        "category": "stealth",
        "description": "Threadless DLL notification execution"
    },
    41: {
        "name": "Decoy Code Execution",
        "category": "stealth",
        "description": "Remote PI with decoy code"
    },
    48: {
        "name": "Sifu Breakpoint Handler (NtResumeThread)",
        "category": "memory_guard",
        "description": "Memory guard with breakpoint on NtResumeThread"
    },
    49: {
        "name": "Sifu Breakpoint Handler (NtCreateThreadEx)",
        "category": "memory_guard",
        "description": "Memory guard with decoy, PAGE_NOACCESS, XOR"
    },
    51: {
        "name": "Sifu Breakpoint Handler (RtlUserThreadStart)",
        "category": "memory_guard",
        "description": "Advanced memory guard on multiple hooks"
    },
    52: {
        "name": "ROP Gadget Trampoline",
        "category": "memory_guard",
        "description": "ROP gadgets for execution trampoline"
    },
    54: {
        "name": "Exception + Breakpoint Handler",
        "category": "memory_guard",
        "description": "Combined exception and breakpoint handling"
    },
    56: {
        "name": "Loader 37 + PEB Module",
        "category": "stealth",
        "description": "Stealth loader with manual PEB module addition"
    },
    57: {
        "name": "RC4 Memory Guard",
        "category": "memory_guard",
        "description": "Loader 51 variant with RC4 encryption"
    },
    58: {
        "name": "VEH + ROP Trampoline",
        "category": "veh_vch",
        "description": "VEH handler with ROP trampoline"
    },
    59: {
        "name": "SEH + ROP Trampoline",
        "category": "veh_vch",
        "description": "SEH handler with ROP trampoline"
    },
    60: {
        "name": "Page Guard Debug Registers",
        "category": "veh_vch",
        "description": "Page guard to set debug registers without Get/SetContext"
    },
    61: {
        "name": "Page Guard VEH/VCH",
        "category": "veh_vch",
        "description": "Page guard + VEH breakpoints + VCH execution"
    },
    63: {
        "name": "Remote Module Injection",
        "category": "stealth",
        "description": "Remote version of custom module loader 37"
    },
    65: {
        "name": "VMT Hooking + Module Loader",
        "category": "threadless",
        "description": "Virtual table hooking with custom module loader"
    },
    66: {
        "name": "VMT + PPID Spoofing",
        "category": "threadless",
        "description": "VMT hooking with PPID spoofing and mitigation policies"
    },
    67: {
        "name": "VMT + Trampoline",
        "category": "threadless",
        "description": "VMT with strange trampoline code"
    },
    69: {
        "name": "Manual VEH/VCH + PEB Cleanup",
        "category": "veh_vch",
        "description": "Manual handler setup with PEB CrossProcessFlags cleanup"
    },
    73: {
        "name": "VT Pointer Threadless",
        "category": "threadless",
        "description": "Virtual table pointer threadless injection with memory guard"
    },
    74: {
        "name": "VT Pointer + Pretext",
        "category": "threadless",
        "description": "VT threadless with VirtualProtect in pretext"
    },
    75: {
        "name": ".NET JIT Threadless",
        "category": "threadless",
        "description": "Dotnet JIT threadless process injection"
    },
    76: {
        "name": "PEB Entrypoint Threadless",
        "category": "threadless",
        "description": "Module list PEB entrypoint hijacking"
    },
    77: {
        "name": "RtlCreateHeap VT Pointer",
        "category": "threadless",
        "description": "VT pointer using RtlCreateHeap instead of BaseThreadInitThunk"
    }
}
