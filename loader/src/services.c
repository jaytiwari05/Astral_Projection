#include <windows.h>
#include "tcg.h"
#define FLAG(x, y) ( ((x) & (y)) == (y) )
/* for the local loader */
__typeof__ ( GetModuleHandle ) * get_module_handle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress )  * get_proc_address  __attribute__ ( ( section ( ".text" ) ) );

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC patch_resolve ( char * mod_name, char * func_name )
{
    HANDLE module = get_module_handle ( mod_name );
    return get_proc_address ( module, func_name );
}
char * findDataCave(char * dllBase, int length) {
    DLLDATA                 data;
    DWORD                   numberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    IMAGE_SECTION_HEADER  * sectionNxt       = NULL;
 
    /* parse our DLL! */
    ParseDLL(dllBase, &data);
 
    /* loop through our sections */
    numberOfSections = data.NtHeaders->FileHeader.NumberOfSections;
    sectionHdr       = (IMAGE_SECTION_HEADER *)PTR_OFFSET(data.OptionalHeader, data.NtHeaders->FileHeader.SizeOfOptionalHeader);
    for (int x = 0; (x + 1) < numberOfSections; x++) {
        /* look for our RW section! */
        if (FLAG(sectionHdr->Characteristics, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
            /* let's look at our next section, we need it to get the right size of the code cave */
            sectionNxt      = sectionHdr + 1;
 
            /* calculate the size, based on section headers */
            DWORD size      = sectionNxt->VirtualAddress - sectionHdr->VirtualAddress;
 
            /* calculate the size of our code cave */
            DWORD cavesize  = size - sectionHdr->SizeOfRawData;
 
            /* if we fit, return it */
            if (length < cavesize)
                return dllBase + (sectionNxt->VirtualAddress - cavesize);
        }
 
        /* advance to our next section */
        sectionHdr++;
    }
 
    return NULL;
}
char * getBSS(DWORD length) {
    /* try in our module */
    HANDLE hModule = KERNEL32$GetModuleHandleA(NULL);
    char * ptr     = findDataCave(hModule, length);
 
    if (ptr != NULL)
        return ptr;
 
    /* try in kernel32 */
    hModule = KERNEL32$GetModuleHandleA("Kernel32");
    ptr     = findDataCave(hModule, length);
    if (ptr != NULL)
        return ptr;
 
    /* it's really bad news if we get here... ka-rash! */
    return NULL;
}