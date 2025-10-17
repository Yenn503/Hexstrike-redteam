global _NtAllocateVirtualMemory_stub
global _NtWriteVirtualMemory_stub
global _NtCreateThreadEx_stub
global _NtWaitForSingleObject_stub

section .text

_NtAllocateVirtualMemory_stub:
    mov r10, rcx                                    
    mov eax, 0x18                                     
    syscall                                         
    ret                                              
                   	 

_NtWriteVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x3A 
    syscall
    ret

_NtCreateThreadEx_stub:
    mov r10, rcx
    mov eax, 0xC7
    syscall
    ret
 
_NtWaitForSingleObject_stub:
    mov r10, rcx
    mov eax, 0x4
    syscall
    ret
 

 
