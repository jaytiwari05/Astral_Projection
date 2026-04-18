#define GETRESOURCE(x) ( char * ) &x

typedef struct {
    int  len;
    char value [ ];
} RESOURCE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef struct _PEB_LDR_DATA2 {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA2;

typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union {
        ULONG Flags;
        struct {
            ULONG PackagedBinary          : 1;
            ULONG MarkedForRemoval        : 1;
            ULONG ImageDll                : 1;
            ULONG LoadNotificationsSent   : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport     : 1;
            ULONG InLegacyLists           : 1;
            ULONG InIndexes               : 1;
            ULONG ShimDll                 : 1;
            ULONG InExceptionTable        : 1;
            ULONG ReservedFlags1          : 2;
            ULONG LoadInProgress          : 1;
            ULONG LoadConfigProcessed     : 1;
            ULONG EntryProcessed          : 1;
            ULONG ProtectDelayLoad        : 1;
            ULONG ReservedFlags3          : 2;
            ULONG DontCallForThreads      : 1;
            ULONG ProcessAttachCalled     : 1;
            ULONG ProcessAttachFailed     : 1;
            ULONG CorDeferredValidate     : 1;
            ULONG CorImage                : 1;
            ULONG DontRelocate            : 1;
            ULONG CorILOnly               : 1;
            ULONG ChpeImage              : 1;
            ULONG ReservedFlags5          : 2;
            ULONG Redirected              : 1;
            ULONG ReservedFlags6          : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY2;


typedef struct {
    HANDLE pSacHandle;
    BOOL Loaded;
} _SacData, *pSacData;
