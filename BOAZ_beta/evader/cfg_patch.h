#ifndef CFG_PATCH_H
#define CFG_PATCH_H

#include <windows.h>  // Provides HANDLE, PVOID, SIZE_T, etc.

PVOID getPattern(unsigned char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size);

int patchCFG(HANDLE hProcess);


#endif 