use crate::types::{CONTEXT, LPCONTEXT, PCONTEXT};
use winapi::ctypes::{c_char, c_int, c_void};
use winapi::shared::basetsd::{
    DWORD_PTR, LONG_PTR, PSIZE_T, PULONG64, PULONG_PTR, SIZE_T, ULONG64, ULONG_PTR,
};
use winapi::shared::evntprov::{
    EVENT_INFO_CLASS, PCEVENT_DESCRIPTOR, PENABLECALLBACK, PEVENT_DATA_DESCRIPTOR, PREGHANDLE,
    REGHANDLE,
};
use winapi::shared::evntrace::{
    PEVENT_TRACE_HEADER, PTRACEHANDLE, PTRACE_GUID_REGISTRATION, TRACEHANDLE, WMIDPREQUEST,
};
use winapi::shared::guiddef::{GUID, LPCGUID, LPGUID};
use winapi::shared::minwindef::{
    BOOL, BYTE, DWORD, FARPROC, FILETIME, HGLOBAL, HINSTANCE, HKEY, HLOCAL, HMODULE, HRSRC, INT,
    LPARAM, LPBOOL, LPBYTE, LPCVOID, LPDWORD, LPFILETIME, LPHANDLE, LPINT, LPLONG, LPVOID, LPWORD,
    PBOOL, PDWORD, PFILETIME, PHKEY, PUCHAR, PUINT, PULONG, PUSHORT, UCHAR, UINT, ULONG, USHORT,
    WORD,
};
use winapi::shared::ntdef::{
    BOOLEAN, CHAR, GROUP_AFFINITY, HANDLE, HRESULT, LANGID, LARGE_INTEGER, LCID, LONG, LONGLONG,
    LPCH, LPCSTR, LPCWCH, LPCWSTR, LPSTR, LPWCH, LPWSTR, PCNZCH, PCNZWCH, PCWSTR, PCZZWSTR,
    PGROUP_AFFINITY, PHANDLE, PLARGE_INTEGER, PLONG, PLUID, PPROCESSOR_NUMBER, PULARGE_INTEGER,
    PULONGLONG, PVOID, PWSTR, PZZWSTR, ULONGLONG, VOID, WCHAR,
};
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::LPTOP_LEVEL_EXCEPTION_FILTER;
use winapi::um::fileapi::{
    LPBY_HANDLE_FILE_INFORMATION, LPCREATEFILE2_EXTENDED_PARAMETERS, STREAM_INFO_LEVELS,
};
use winapi::um::heapapi::LPHEAP_SUMMARY;
use winapi::um::libloaderapi::{
    DLL_DIRECTORY_COOKIE, ENUMRESLANGPROCA, ENUMRESLANGPROCW, ENUMRESNAMEPROCA, ENUMRESNAMEPROCW,
    ENUMRESTYPEPROCA, ENUMRESTYPEPROCW,
};
use winapi::um::memoryapi::{
    MEMORY_RESOURCE_NOTIFICATION_TYPE, OFFER_PRIORITY, PBAD_MEMORY_CALLBACK_ROUTINE,
    PWIN32_MEMORY_RANGE_ENTRY,
};
use winapi::um::minwinbase::{
    FILE_INFO_BY_HANDLE_CLASS, FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS, GET_FILEEX_INFO_LEVELS,
    LPCRITICAL_SECTION, LPDEBUG_EVENT, LPENCLAVE_ROUTINE, LPOVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE, LPOVERLAPPED_ENTRY, LPPROCESS_HEAP_ENTRY,
    LPSECURITY_ATTRIBUTES, LPSYSTEMTIME, LPTHREAD_START_ROUTINE, LPWIN32_FIND_DATAA,
    LPWIN32_FIND_DATAW, PCRITICAL_SECTION, PREASON_CONTEXT, PSECURITY_ATTRIBUTES,
    SECURITY_ATTRIBUTES, SYSTEMTIME,
};
use winapi::um::perflib::{
    PERFLIBREQUEST, PPERF_COUNTERSET_INFO, PPERF_COUNTERSET_INSTANCE, PPERF_PROVIDER_CONTEXT,
};
use winapi::um::processsnapshot::{
    HPSS, HPSSWALK, PSS_ALLOCATOR, PSS_CAPTURE_FLAGS, PSS_DUPLICATE_FLAGS,
    PSS_QUERY_INFORMATION_CLASS, PSS_WALK_INFORMATION_CLASS,
};
use winapi::um::processthreadsapi::{
    LPPROCESS_INFORMATION, LPPROC_THREAD_ATTRIBUTE_LIST, LPSTARTUPINFOA, LPSTARTUPINFOW,
    PROCESS_INFORMATION_CLASS, THREAD_INFORMATION_CLASS,
};
use winapi::um::psapi::{
    LPMODULEINFO, PENUM_PAGE_FILE_CALLBACKA, PENUM_PAGE_FILE_CALLBACKW, PPERFORMANCE_INFORMATION,
    PPROCESS_MEMORY_COUNTERS, PPSAPI_WS_WATCH_INFORMATION, PPSAPI_WS_WATCH_INFORMATION_EX,
};
use winapi::um::synchapi::{
    LPINIT_ONCE, LPSYNCHRONIZATION_BARRIER, PCONDITION_VARIABLE, PINIT_ONCE, PINIT_ONCE_FN,
    PSRWLOCK, PTIMERAPCROUTINE,
};
use winapi::um::sysinfoapi::{COMPUTER_NAME_FORMAT, LPMEMORYSTATUSEX, LPSYSTEM_INFO};
use winapi::um::threadpoolapiset::PTP_WIN32_IO_CALLBACK;
use winapi::um::timezoneapi::{
    DYNAMIC_TIME_ZONE_INFORMATION, LPTIME_ZONE_INFORMATION, PDYNAMIC_TIME_ZONE_INFORMATION,
    TIME_ZONE_INFORMATION,
};
use winapi::um::werapi::WER_REGISTER_FILE_TYPE;
use winapi::um::winbase::{
    APPLICATION_RECOVERY_CALLBACK, COPYFILE2_EXTENDED_PARAMETERS, LPCOMMCONFIG, LPCOMMPROP,
    LPCOMMTIMEOUTS, LPCOMSTAT, LPDCB, LPFIBER_START_ROUTINE, LPFILE_ID_DESCRIPTOR,
    LPPROGRESS_ROUTINE, PACTCTX_SECTION_KEYED_DATA, PCACTCTXW,
};
use winapi::um::wincon::{
    CONSOLE_CURSOR_INFO, PCONSOLE_CURSOR_INFO, PCONSOLE_FONT_INFOEX, PCONSOLE_HISTORY_INFO,
    PCONSOLE_READCONSOLE_CONTROL, PCONSOLE_SCREEN_BUFFER_INFO, PCONSOLE_SCREEN_BUFFER_INFOEX,
    PCONSOLE_SELECTION_INFO, PHANDLER_ROUTINE,
};
use winapi::um::wincontypes::{
    CHAR_INFO, COORD, HPCON, INPUT_RECORD, PCHAR_INFO, PCONSOLE_FONT_INFO, PCOORD, PINPUT_RECORD,
    PSMALL_RECT, SMALL_RECT,
};
use winapi::um::winnls::{
    CALID, CALINFO_ENUMPROCEXEX, CALINFO_ENUMPROCEXW, CALINFO_ENUMPROCW, CALTYPE,
    CODEPAGE_ENUMPROCW, CURRENCYFMTW, DATEFMT_ENUMPROCEXEX, DATEFMT_ENUMPROCEXW, DATEFMT_ENUMPROCW,
    GEOCLASS, GEOID, GEOTYPE, GEO_ENUMPROC, LANGGROUPLOCALE_ENUMPROCW, LANGUAGEGROUP_ENUMPROCW,
    LCTYPE, LGRPID, LOCALE_ENUMPROCA, LOCALE_ENUMPROCEX, LOCALE_ENUMPROCW, LPCPINFO, LPCPINFOEXW,
    LPNLSVERSIONINFO, LPNLSVERSIONINFOEX, NLS_FUNCTION, NORM_FORM, NUMBERFMTW, PFILEMUIINFO,
    TIMEFMT_ENUMPROCEX, TIMEFMT_ENUMPROCW, UILANGUAGE_ENUMPROCW,
};
use winapi::um::winnt::{
    ACL_INFORMATION_CLASS, AUDIT_EVENT_TYPE, EXCEPTION_POINTERS, FILE_SEGMENT_ELEMENT,
    HEAP_INFORMATION_CLASS, LOGICAL_PROCESSOR_RELATIONSHIP, LPOSVERSIONINFOA, LPOSVERSIONINFOW,
    PACL, PAPCFUNC, PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PEXCEPTION_RECORD,
    PFLS_CALLBACK_FUNCTION, PGENERIC_MAPPING, PLUID_AND_ATTRIBUTES, PMEMORY_BASIC_INFORMATION,
    POBJECT_TYPE_LIST, PPRIVILEGE_SET, PROCESS_MITIGATION_POLICY, PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR_CONTROL, PSID, PSID_AND_ATTRIBUTES, PSID_IDENTIFIER_AUTHORITY,
    PSLIST_ENTRY, PSLIST_HEADER, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
    PTP_CALLBACK_ENVIRON, PTP_CALLBACK_INSTANCE, PTP_CLEANUP_GROUP, PTP_IO, PTP_POOL,
    PTP_POOL_STACK_INFORMATION, PTP_SIMPLE_CALLBACK, PTP_TIMER, PTP_TIMER_CALLBACK, PTP_WAIT,
    PTP_WAIT_CALLBACK, PTP_WORK, PTP_WORK_CALLBACK, PVECTORED_EXCEPTION_HANDLER, PWOW64_CONTEXT,
    SECURITY_DESCRIPTOR_CONTROL, SECURITY_IMPERSONATION_LEVEL, SECURITY_INFORMATION,
    TOKEN_INFORMATION_CLASS, TOKEN_TYPE, WAITORTIMERCALLBACK, WELL_KNOWN_SID_TYPE, WOW64_CONTEXT,
};
use winapi::um::winreg::{LSTATUS, PVALENTA, PVALENTW, REGSAM};
use winapi::vc::vadefs::va_list;

pub type FnAccessCheck = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    HANDLE,
    DWORD,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    LPDWORD,
    LPDWORD,
    LPBOOL,
) -> BOOL;
pub type FnAccessCheckAndAuditAlarmW = unsafe extern "system" fn(
    LPCWSTR,
    LPVOID,
    LPWSTR,
    LPWSTR,
    PSECURITY_DESCRIPTOR,
    DWORD,
    PGENERIC_MAPPING,
    BOOL,
    LPDWORD,
    LPBOOL,
    LPBOOL,
) -> BOOL;
pub type FnAccessCheckByType = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    DWORD,
    POBJECT_TYPE_LIST,
    DWORD,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    LPDWORD,
    LPDWORD,
    LPBOOL,
) -> BOOL;
pub type FnAccessCheckByTypeAndAuditAlarmW = unsafe extern "system" fn(
    LPCWSTR,
    LPVOID,
    LPWSTR,
    LPCWSTR,
    PSECURITY_DESCRIPTOR,
    PSID,
    DWORD,
    AUDIT_EVENT_TYPE,
    DWORD,
    POBJECT_TYPE_LIST,
    DWORD,
    PGENERIC_MAPPING,
    BOOL,
    LPDWORD,
    LPBOOL,
    LPBOOL,
) -> BOOL;
pub type FnAccessCheckByTypeResultList = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    DWORD,
    POBJECT_TYPE_LIST,
    DWORD,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    LPDWORD,
    LPDWORD,
    LPDWORD,
) -> BOOL;
pub type FnAccessCheckByTypeResultListAndAuditAlarmByHandleW = unsafe extern "system" fn(
    LPCWSTR,
    LPVOID,
    HANDLE,
    LPCWSTR,
    LPCWSTR,
    PSECURITY_DESCRIPTOR,
    PSID,
    DWORD,
    AUDIT_EVENT_TYPE,
    DWORD,
    POBJECT_TYPE_LIST,
    DWORD,
    PGENERIC_MAPPING,
    BOOL,
    LPDWORD,
    LPDWORD,
    LPBOOL,
) -> BOOL;
pub type FnAccessCheckByTypeResultListAndAuditAlarmW = unsafe extern "system" fn(
    LPCWSTR,
    LPVOID,
    LPCWSTR,
    LPCWSTR,
    PSECURITY_DESCRIPTOR,
    PSID,
    DWORD,
    AUDIT_EVENT_TYPE,
    DWORD,
    POBJECT_TYPE_LIST,
    DWORD,
    PGENERIC_MAPPING,
    BOOL,
    LPDWORD,
    LPDWORD,
    LPBOOL,
) -> BOOL;
pub type FnAcquireSRWLockExclusive = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnAcquireSRWLockShared = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnActivateActCtx = unsafe extern "system" fn(HANDLE, *mut ULONG_PTR) -> BOOL;
pub type FnAddAccessAllowedAce = unsafe extern "system" fn(PACL, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddAccessAllowedAceEx =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddAccessAllowedObjectAce =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, *mut GUID, *mut GUID, PSID) -> BOOL;
pub type FnAddAccessDeniedAce = unsafe extern "system" fn(PACL, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddAccessDeniedAceEx =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddAccessDeniedObjectAce =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, *mut GUID, *mut GUID, PSID) -> BOOL;
pub type FnAddAce = unsafe extern "system" fn(PACL, DWORD, DWORD, LPVOID, DWORD) -> BOOL;
pub type FnAddAuditAccessAce =
    unsafe extern "system" fn(PACL, DWORD, DWORD, PSID, BOOL, BOOL) -> BOOL;
pub type FnAddAuditAccessAceEx =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID, BOOL, BOOL) -> BOOL;
pub type FnAddAuditAccessObjectAce = unsafe extern "system" fn(
    PACL,
    DWORD,
    DWORD,
    DWORD,
    *mut GUID,
    *mut GUID,
    PSID,
    BOOL,
    BOOL,
) -> BOOL;
pub type FnAddConsoleAliasA = unsafe extern "system" fn(LPSTR, LPSTR, LPSTR) -> BOOL;
pub type FnAddConsoleAliasW = unsafe extern "system" fn(LPWSTR, LPWSTR, LPWSTR) -> BOOL;
pub type FnAddDllDirectory = unsafe extern "system" fn(PCWSTR) -> DLL_DIRECTORY_COOKIE;
pub type FnAddMandatoryAce = unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddRefActCtx = unsafe extern "system" fn(HANDLE) -> ();
pub type FnAddResourceAttributeAce = unsafe extern "system" fn(
    PACL,
    DWORD,
    DWORD,
    DWORD,
    PSID,
    PCLAIM_SECURITY_ATTRIBUTES_INFORMATION,
    PDWORD,
) -> BOOL;
pub type FnAddSIDToBoundaryDescriptor = unsafe extern "system" fn(*mut HANDLE, PSID) -> BOOL;
pub type FnAddScopedPolicyIDAce =
    unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddVectoredContinueHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnAddVectoredExceptionHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnAdjustTokenGroups =
    unsafe extern "system" fn(HANDLE, BOOL, PTOKEN_GROUPS, DWORD, PTOKEN_GROUPS, PDWORD) -> BOOL;
pub type FnAdjustTokenPrivileges = unsafe extern "system" fn(
    HANDLE,
    BOOL,
    PTOKEN_PRIVILEGES,
    DWORD,
    PTOKEN_PRIVILEGES,
    PDWORD,
) -> BOOL;
pub type FnAllocConsole = unsafe extern "system" fn() -> BOOL;
pub type FnAllocateAndInitializeSid = unsafe extern "system" fn(
    PSID_IDENTIFIER_AUTHORITY,
    BYTE,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    *mut PSID,
) -> BOOL;
pub type FnAllocateLocallyUniqueId = unsafe extern "system" fn(PLUID) -> BOOL;
pub type FnAllocateUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnAllocateUserPhysicalPagesNuma =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR, DWORD) -> BOOL;
pub type FnAreAllAccessesGranted = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnAreAnyAccessesGranted = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnAreFileApisANSI = unsafe extern "system" fn() -> BOOL;
pub type FnAttachConsole = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnBeep = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnCallEnclave =
    unsafe extern "system" fn(LPENCLAVE_ROUTINE, LPVOID, BOOL, *mut LPVOID) -> BOOL;
pub type FnCallNamedPipeW =
    unsafe extern "system" fn(LPCWSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD) -> BOOL;
pub type FnCallbackMayRunLong = unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> BOOL;
pub type FnCancelIo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCancelIoEx = unsafe extern "system" fn(HANDLE, LPOVERLAPPED) -> BOOL;
pub type FnCancelSynchronousIo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCancelThreadpoolIo = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnCancelWaitableTimer = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCeipIsOptedIn = unsafe extern "system" fn() -> BOOL;
pub type FnChangeTimerQueueTimer = unsafe extern "system" fn(HANDLE, HANDLE, ULONG, ULONG) -> BOOL;
pub type FnCharLowerA = unsafe extern "system" fn(LPSTR) -> LPSTR;
pub type FnCharLowerBuffA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnCharLowerBuffW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnCharLowerW = unsafe extern "system" fn(LPWSTR) -> LPWSTR;
pub type FnCharNextA = unsafe extern "system" fn(LPCSTR) -> LPSTR;
pub type FnCharNextExA = unsafe extern "system" fn(WORD, LPSTR, DWORD) -> LPSTR;
pub type FnCharNextW = unsafe extern "system" fn(LPCWSTR) -> LPWSTR;
pub type FnCharPrevA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> LPSTR;
pub type FnCharPrevExA = unsafe extern "system" fn(WORD, LPCSTR, LPCSTR, DWORD) -> LPSTR;
pub type FnCharPrevW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> LPWSTR;
pub type FnCharUpperA = unsafe extern "system" fn(LPSTR) -> LPSTR;
pub type FnCharUpperBuffA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnCharUpperBuffW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnCharUpperW = unsafe extern "system" fn(LPWSTR) -> LPWSTR;
pub type FnCheckRemoteDebuggerPresent = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnCheckTokenCapability = unsafe extern "system" fn(HANDLE, PSID, PBOOL) -> BOOL;
pub type FnCheckTokenMembership = unsafe extern "system" fn(HANDLE, PSID, PBOOL) -> BOOL;
pub type FnCheckTokenMembershipEx = unsafe extern "system" fn(HANDLE, PSID, DWORD, PBOOL) -> BOOL;
pub type FnClearCommBreak = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnClearCommError = unsafe extern "system" fn(HANDLE, LPDWORD, LPCOMSTAT) -> BOOL;
pub type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnClosePrivateNamespace = unsafe extern "system" fn(HANDLE, ULONG) -> BOOLEAN;
pub type FnClosePseudoConsole = unsafe extern "system" fn(HPCON) -> ();
pub type FnCloseThreadpool = unsafe extern "system" fn(PTP_POOL) -> ();
pub type FnCloseThreadpoolCleanupGroup = unsafe extern "system" fn(PTP_CLEANUP_GROUP) -> ();
pub type FnCloseThreadpoolCleanupGroupMembers =
    unsafe extern "system" fn(PTP_CLEANUP_GROUP, BOOL, PVOID) -> ();
pub type FnCloseThreadpoolIo = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnCloseThreadpoolTimer = unsafe extern "system" fn(PTP_TIMER) -> ();
pub type FnCloseThreadpoolWait = unsafe extern "system" fn(PTP_WAIT) -> ();
pub type FnCloseThreadpoolWork = unsafe extern "system" fn(PTP_WORK) -> ();
pub type FnCommandLineToArgvW = unsafe extern "system" fn(LPCWSTR, *mut c_int) -> ();
pub type FnCompareFileTime = unsafe extern "system" fn(*const FILETIME, *const FILETIME) -> LONG;
pub type FnCompareObjectHandles = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnCompareStringA =
    unsafe extern "system" fn(LCID, DWORD, PCNZCH, c_int, PCNZCH, c_int) -> c_int;
pub type FnCompareStringEx = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    LPCWCH,
    c_int,
    LPCWCH,
    c_int,
    LPNLSVERSIONINFO,
    LPVOID,
    LPARAM,
) -> c_int;
pub type FnCompareStringOrdinal =
    unsafe extern "system" fn(LPCWCH, c_int, LPCWCH, c_int, BOOL) -> c_int;
pub type FnCompareStringW =
    unsafe extern "system" fn(LCID, DWORD, PCNZWCH, c_int, PCNZWCH, c_int) -> c_int;
pub type FnConnectNamedPipe = unsafe extern "system" fn(HANDLE, LPOVERLAPPED) -> BOOL;
pub type FnContinueDebugEvent = unsafe extern "system" fn(DWORD, DWORD, DWORD) -> BOOL;
pub type FnConvertDefaultLocale = unsafe extern "system" fn(LCID) -> LCID;
pub type FnConvertFiberToThread = unsafe extern "system" fn() -> BOOL;
pub type FnConvertThreadToFiber = unsafe extern "system" fn(LPVOID) -> LPVOID;
pub type FnConvertThreadToFiberEx = unsafe extern "system" fn(LPVOID, DWORD) -> LPVOID;
pub type FnConvertToAutoInheritPrivateObjectSecurity = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    *mut GUID,
    BOOLEAN,
    PGENERIC_MAPPING,
) -> BOOL;
pub type FnCopyContext = unsafe extern "system" fn(PCONTEXT, DWORD, PCONTEXT) -> BOOL;
pub type FnCopyFile2 =
    unsafe extern "system" fn(PCWSTR, PCWSTR, *mut COPYFILE2_EXTENDED_PARAMETERS) -> HRESULT;
pub type FnCopyFileExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD) -> BOOL;
pub type FnCopyFileW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, BOOL) -> BOOL;
pub type FnCopySid = unsafe extern "system" fn(DWORD, PSID, PSID) -> BOOL;
pub type FnCreateActCtxW = unsafe extern "system" fn(PCACTCTXW) -> HANDLE;
pub type FnCreateBoundaryDescriptorW = unsafe extern "system" fn(LPCWSTR, ULONG) -> HANDLE;
pub type FnCreateConsoleScreenBuffer =
    unsafe extern "system" fn(DWORD, DWORD, *const SECURITY_ATTRIBUTES, DWORD, LPVOID) -> HANDLE;
pub type FnCreateDirectoryA = unsafe extern "system" fn(LPCSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateDirectoryExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateDirectoryW = unsafe extern "system" fn(LPCWSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateEnclave = unsafe extern "system" fn(
    HANDLE,
    LPVOID,
    SIZE_T,
    SIZE_T,
    DWORD,
    LPCVOID,
    DWORD,
    LPDWORD,
) -> LPVOID;
pub type FnCreateEventA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR) -> HANDLE;
pub type FnCreateEventExA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateEventExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateEventW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR) -> HANDLE;
pub type FnCreateFiber = unsafe extern "system" fn(SIZE_T, LPFIBER_START_ROUTINE, LPVOID) -> LPVOID;
pub type FnCreateFiberEx =
    unsafe extern "system" fn(SIZE_T, SIZE_T, DWORD, LPFIBER_START_ROUTINE, LPVOID) -> LPVOID;
pub type FnCreateFile2 = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    DWORD,
    LPCREATEFILE2_EXTENDED_PARAMETERS,
) -> HANDLE;
pub type FnCreateFileA = unsafe extern "system" fn(
    LPCSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE,
) -> HANDLE;
pub type FnCreateFileMappingFromApp =
    unsafe extern "system" fn(HANDLE, PSECURITY_ATTRIBUTES, ULONG, ULONG64, PCWSTR) -> HANDLE;
pub type FnCreateFileMappingNumaW = unsafe extern "system" fn(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    DWORD,
    LPCWSTR,
    DWORD,
) -> HANDLE;
pub type FnCreateFileMappingW = unsafe extern "system" fn(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    DWORD,
    LPCWSTR,
) -> HANDLE;
pub type FnCreateFileW = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE,
) -> HANDLE;
pub type FnCreateHardLinkA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateHardLinkW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateIoCompletionPort =
    unsafe extern "system" fn(HANDLE, HANDLE, ULONG_PTR, DWORD) -> HANDLE;
pub type FnCreateMemoryResourceNotification =
    unsafe extern "system" fn(MEMORY_RESOURCE_NOTIFICATION_TYPE) -> HANDLE;
pub type FnCreateMutexA = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR) -> HANDLE;
pub type FnCreateMutexExA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateMutexExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateMutexW = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) -> HANDLE;
pub type FnCreateNamedPipeW = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
) -> HANDLE;
pub type FnCreatePipe =
    unsafe extern "system" fn(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD) -> BOOL;
pub type FnCreatePrivateNamespaceW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR) -> HANDLE;
pub type FnCreatePrivateObjectSecurity = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    BOOL,
    HANDLE,
    PGENERIC_MAPPING,
) -> BOOL;
pub type FnCreatePrivateObjectSecurityEx = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    *mut GUID,
    BOOL,
    ULONG,
    HANDLE,
    PGENERIC_MAPPING,
) -> BOOL;
pub type FnCreatePrivateObjectSecurityWithMultipleInheritance = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    ULONG,
    BOOL,
    ULONG,
    HANDLE,
    PGENERIC_MAPPING,
) -> BOOL;
pub type FnCreateProcessA = unsafe extern "system" fn(
    LPCSTR,
    LPSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCSTR,
    LPSTARTUPINFOA,
    LPPROCESS_INFORMATION,
) -> BOOL;
pub type FnCreateProcessAsUserW = unsafe extern "system" fn(
    HANDLE,
    LPCWSTR,
    LPWSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCWSTR,
    LPSTARTUPINFOW,
    LPPROCESS_INFORMATION,
) -> BOOL;
pub type FnCreateProcessW = unsafe extern "system" fn(
    LPCWSTR,
    LPWSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCWSTR,
    LPSTARTUPINFOW,
    LPPROCESS_INFORMATION,
) -> BOOL;
pub type FnCreatePseudoConsole =
    unsafe extern "system" fn(COORD, HANDLE, HANDLE, DWORD, *mut HPCON) -> HRESULT;
pub type FnCreateRemoteThread = unsafe extern "system" fn(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    DWORD,
    LPDWORD,
) -> HANDLE;
pub type FnCreateRemoteThreadEx = unsafe extern "system" fn(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    DWORD,
    LPPROC_THREAD_ATTRIBUTE_LIST,
    LPDWORD,
) -> HANDLE;
pub type FnCreateRestrictedToken = unsafe extern "system" fn(
    HANDLE,
    DWORD,
    DWORD,
    PSID_AND_ATTRIBUTES,
    DWORD,
    PLUID_AND_ATTRIBUTES,
    DWORD,
    PSID_AND_ATTRIBUTES,
    PHANDLE,
) -> BOOL;
pub type FnCreateSemaphoreExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateSemaphoreW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR) -> HANDLE;
pub type FnCreateSymbolicLinkW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD) -> BOOLEAN;
pub type FnCreateThread = unsafe extern "system" fn(
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    DWORD,
    LPDWORD,
) -> HANDLE;
pub type FnCreateThreadpool = unsafe extern "system" fn(PVOID) -> PTP_POOL;
pub type FnCreateThreadpoolCleanupGroup = unsafe extern "system" fn() -> PTP_CLEANUP_GROUP;
pub type FnCreateThreadpoolIo =
    unsafe extern "system" fn(HANDLE, PTP_WIN32_IO_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> PTP_IO;
pub type FnCreateThreadpoolTimer =
    unsafe extern "system" fn(PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> PTP_TIMER;
pub type FnCreateThreadpoolWait =
    unsafe extern "system" fn(PTP_WAIT_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> PTP_WAIT;
pub type FnCreateThreadpoolWork =
    unsafe extern "system" fn(PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> PTP_WORK;
pub type FnCreateTimerQueue = unsafe extern "system" fn() -> HANDLE;
pub type FnCreateTimerQueueTimer = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    WAITORTIMERCALLBACK,
    PVOID,
    DWORD,
    DWORD,
    ULONG,
) -> BOOL;
pub type FnCreateWaitableTimerExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateWaitableTimerW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) -> HANDLE;
pub type FnCreateWellKnownSid =
    unsafe extern "system" fn(WELL_KNOWN_SID_TYPE, PSID, PSID, *mut DWORD) -> BOOL;
pub type FnCveEventWrite = unsafe extern "system" fn(PCWSTR, PCWSTR) -> LONG;
pub type FnDeactivateActCtx = unsafe extern "system" fn(DWORD, ULONG_PTR) -> BOOL;
pub type FnDebugActiveProcess = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnDebugActiveProcessStop = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnDebugBreak = unsafe extern "system" fn() -> ();
pub type FnDecodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnDecodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnDefineDosDeviceW = unsafe extern "system" fn(DWORD, LPCWSTR, LPCWSTR) -> BOOL;
pub type FnDeleteAce = unsafe extern "system" fn(PACL, DWORD) -> BOOL;
pub type FnDeleteBoundaryDescriptor = unsafe extern "system" fn(HANDLE) -> ();
pub type FnDeleteCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnDeleteEnclave = unsafe extern "system" fn(LPVOID) -> BOOL;
pub type FnDeleteFiber = unsafe extern "system" fn(LPVOID) -> ();
pub type FnDeleteFileA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnDeleteFileW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnDeleteProcThreadAttributeList =
    unsafe extern "system" fn(LPPROC_THREAD_ATTRIBUTE_LIST) -> ();
pub type FnDeleteSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER) -> BOOL;
pub type FnDeleteTimerQueue = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDeleteTimerQueueEx = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnDeleteTimerQueueTimer = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> BOOL;
pub type FnDeleteVolumeMountPointW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnDeriveCapabilitySidsFromName =
    unsafe extern "system" fn(LPCWSTR, *mut DWORD, *mut DWORD) -> BOOL;
pub type FnDestroyPrivateObjectSecurity =
    unsafe extern "system" fn(*mut PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnDeviceIoControl = unsafe extern "system" fn(
    HANDLE,
    DWORD,
    LPVOID,
    DWORD,
    LPVOID,
    DWORD,
    LPDWORD,
    LPOVERLAPPED,
) -> BOOL;
pub type FnDisableThreadLibraryCalls = unsafe extern "system" fn(HMODULE) -> BOOL;
pub type FnDisassociateCurrentThreadFromCallback =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> ();
pub type FnDiscardVirtualMemory = unsafe extern "system" fn(PVOID, SIZE_T) -> DWORD;
pub type FnDisconnectNamedPipe = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDnsHostnameToComputerNameExW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, LPDWORD) -> BOOL;
pub type FnDuplicateHandle =
    unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) -> BOOL;
pub type FnDuplicateToken =
    unsafe extern "system" fn(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE) -> BOOL;
pub type FnDuplicateTokenEx = unsafe extern "system" fn(
    HANDLE,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    SECURITY_IMPERSONATION_LEVEL,
    TOKEN_TYPE,
    PHANDLE,
) -> BOOL;
pub type FnEmptyWorkingSet = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnEncodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnEncodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnEnterCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnEnterSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER, DWORD) -> BOOL;
pub type FnEnumCalendarInfoExEx = unsafe extern "system" fn(
    CALINFO_ENUMPROCEXEX,
    LPCWSTR,
    CALID,
    LPCWSTR,
    CALTYPE,
    LPARAM,
) -> BOOL;
pub type FnEnumCalendarInfoExW =
    unsafe extern "system" fn(CALINFO_ENUMPROCEXW, LCID, CALID, CALTYPE) -> BOOL;
pub type FnEnumCalendarInfoW =
    unsafe extern "system" fn(CALINFO_ENUMPROCW, LCID, CALID, CALTYPE) -> BOOL;
pub type FnEnumDateFormatsExEx =
    unsafe extern "system" fn(DATEFMT_ENUMPROCEXEX, LPCWSTR, DWORD, LPARAM) -> BOOL;
pub type FnEnumDateFormatsExW = unsafe extern "system" fn(DATEFMT_ENUMPROCEXW, LCID, DWORD) -> BOOL;
pub type FnEnumDateFormatsW = unsafe extern "system" fn(DATEFMT_ENUMPROCW, LCID, DWORD) -> BOOL;
pub type FnEnumDeviceDrivers = unsafe extern "system" fn(*mut LPVOID, DWORD, LPDWORD) -> BOOL;
pub type FnEnumDynamicTimeZoneInformation =
    unsafe extern "system" fn(DWORD, PDYNAMIC_TIME_ZONE_INFORMATION) -> DWORD;
pub type FnEnumLanguageGroupLocalesW =
    unsafe extern "system" fn(LANGGROUPLOCALE_ENUMPROCW, LGRPID, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumPageFilesA = unsafe extern "system" fn(PENUM_PAGE_FILE_CALLBACKA, LPVOID) -> BOOL;
pub type FnEnumPageFilesW = unsafe extern "system" fn(PENUM_PAGE_FILE_CALLBACKW, LPVOID) -> BOOL;
pub type FnEnumProcessModules =
    unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, LPDWORD) -> BOOL;
pub type FnEnumProcessModulesEx =
    unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, LPDWORD, DWORD) -> BOOL;
pub type FnEnumProcesses = unsafe extern "system" fn(*mut DWORD, DWORD, LPDWORD) -> BOOL;
pub type FnEnumResourceLanguagesExA = unsafe extern "system" fn(
    HMODULE,
    LPCSTR,
    LPCSTR,
    ENUMRESLANGPROCA,
    LONG_PTR,
    DWORD,
    LANGID,
) -> BOOL;
pub type FnEnumResourceLanguagesExW = unsafe extern "system" fn(
    HMODULE,
    LPCWSTR,
    LPCWSTR,
    ENUMRESLANGPROCW,
    LONG_PTR,
    DWORD,
    LANGID,
) -> BOOL;
pub type FnEnumResourceNamesA =
    unsafe extern "system" fn(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR) -> BOOL;
pub type FnEnumResourceNamesExA =
    unsafe extern "system" fn(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceNamesExW =
    unsafe extern "system" fn(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceNamesW =
    unsafe extern "system" fn(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR) -> BOOL;
pub type FnEnumResourceTypesExA =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCA, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceTypesExW =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCW, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumSystemCodePagesW = unsafe extern "system" fn(CODEPAGE_ENUMPROCW, DWORD) -> BOOL;
pub type FnEnumSystemFirmwareTables = unsafe extern "system" fn(DWORD, PVOID, DWORD) -> UINT;
pub type FnEnumSystemGeoID = unsafe extern "system" fn(GEOCLASS, GEOID, GEO_ENUMPROC) -> BOOL;
pub type FnEnumSystemLanguageGroupsW =
    unsafe extern "system" fn(LANGUAGEGROUP_ENUMPROCW, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumSystemLocalesA = unsafe extern "system" fn(LOCALE_ENUMPROCA, DWORD) -> BOOL;
pub type FnEnumSystemLocalesEx =
    unsafe extern "system" fn(LOCALE_ENUMPROCEX, DWORD, LPARAM, LPVOID) -> BOOL;
pub type FnEnumSystemLocalesW = unsafe extern "system" fn(LOCALE_ENUMPROCW, DWORD) -> BOOL;
pub type FnEnumTimeFormatsEx =
    unsafe extern "system" fn(TIMEFMT_ENUMPROCEX, LPCWSTR, DWORD, LPARAM) -> BOOL;
pub type FnEnumTimeFormatsW = unsafe extern "system" fn(TIMEFMT_ENUMPROCW, LCID, DWORD) -> BOOL;
pub type FnEnumUILanguagesW =
    unsafe extern "system" fn(UILANGUAGE_ENUMPROCW, DWORD, LONG_PTR) -> BOOL;
pub type FnEqualDomainSid = unsafe extern "system" fn(PSID, PSID, *mut BOOL) -> BOOL;
pub type FnEqualPrefixSid = unsafe extern "system" fn(PSID, PSID) -> BOOL;
pub type FnEqualSid = unsafe extern "system" fn(PSID, PSID) -> BOOL;
pub type FnEscapeCommFunction = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnEventActivityIdControl = unsafe extern "system" fn(ULONG, LPGUID) -> ULONG;
pub type FnEventEnabled = unsafe extern "system" fn(REGHANDLE, PCEVENT_DESCRIPTOR) -> BOOLEAN;
pub type FnEventProviderEnabled = unsafe extern "system" fn(REGHANDLE, UCHAR, ULONGLONG) -> BOOLEAN;
pub type FnEventRegister =
    unsafe extern "system" fn(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE) -> ULONG;
pub type FnEventSetInformation =
    unsafe extern "system" fn(REGHANDLE, EVENT_INFO_CLASS, PVOID, ULONG) -> ULONG;
pub type FnEventUnregister = unsafe extern "system" fn(REGHANDLE) -> ULONG;
pub type FnEventWrite = unsafe extern "system" fn(
    REGHANDLE,
    PCEVENT_DESCRIPTOR,
    ULONG,
    PEVENT_DATA_DESCRIPTOR,
) -> ULONG;
pub type FnEventWriteEx = unsafe extern "system" fn(
    REGHANDLE,
    PCEVENT_DESCRIPTOR,
    ULONG64,
    ULONG,
    LPCGUID,
    LPCGUID,
    ULONG,
    PEVENT_DATA_DESCRIPTOR,
) -> ULONG;
pub type FnEventWriteString =
    unsafe extern "system" fn(REGHANDLE, UCHAR, ULONGLONG, PCWSTR) -> ULONG;
pub type FnEventWriteTransfer = unsafe extern "system" fn(
    REGHANDLE,
    PCEVENT_DESCRIPTOR,
    LPCGUID,
    LPCGUID,
    ULONG,
    PEVENT_DATA_DESCRIPTOR,
) -> ULONG;
pub type FnExitProcess = unsafe extern "system" fn(UINT) -> ();
pub type FnExitThread = unsafe extern "system" fn(DWORD) -> ();
pub type FnExpandEnvironmentStringsA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnExpandEnvironmentStringsW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnFatalAppExitA = unsafe extern "system" fn(UINT, LPCSTR) -> ();
pub type FnFatalAppExitW = unsafe extern "system" fn(UINT, LPCWSTR) -> ();
pub type FnFileTimeToLocalFileTime = unsafe extern "system" fn(*const FILETIME, LPFILETIME) -> BOOL;
pub type FnFileTimeToSystemTime = unsafe extern "system" fn(*const FILETIME, LPSYSTEMTIME) -> BOOL;
pub type FnFillConsoleOutputAttribute =
    unsafe extern "system" fn(HANDLE, WORD, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnFillConsoleOutputCharacterA =
    unsafe extern "system" fn(HANDLE, CHAR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnFillConsoleOutputCharacterW =
    unsafe extern "system" fn(HANDLE, WCHAR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnFindActCtxSectionGuid = unsafe extern "system" fn(
    DWORD,
    *const GUID,
    ULONG,
    *const GUID,
    PACTCTX_SECTION_KEYED_DATA,
) -> BOOL;
pub type FnFindActCtxSectionStringW = unsafe extern "system" fn(
    DWORD,
    *const GUID,
    ULONG,
    LPCWSTR,
    PACTCTX_SECTION_KEYED_DATA,
) -> BOOL;
pub type FnFindClose = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFindCloseChangeNotification = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFindFirstChangeNotificationA = unsafe extern "system" fn(LPCSTR, BOOL, DWORD) -> HANDLE;
pub type FnFindFirstChangeNotificationW = unsafe extern "system" fn(LPCWSTR, BOOL, DWORD) -> HANDLE;
pub type FnFindFirstFileA = unsafe extern "system" fn(LPCSTR, LPWIN32_FIND_DATAA) -> HANDLE;
pub type FnFindFirstFileExA = unsafe extern "system" fn(
    LPCSTR,
    FINDEX_INFO_LEVELS,
    LPVOID,
    FINDEX_SEARCH_OPS,
    LPVOID,
    DWORD,
) -> HANDLE;
pub type FnFindFirstFileExW = unsafe extern "system" fn(
    LPCWSTR,
    FINDEX_INFO_LEVELS,
    LPVOID,
    FINDEX_SEARCH_OPS,
    LPVOID,
    DWORD,
) -> HANDLE;
pub type FnFindFirstFileNameW = unsafe extern "system" fn(LPCWSTR, DWORD, LPDWORD, PWSTR) -> HANDLE;
pub type FnFindFirstFileW = unsafe extern "system" fn(LPCWSTR, LPWIN32_FIND_DATAW) -> HANDLE;
pub type FnFindFirstFreeAce = unsafe extern "system" fn(PACL, *mut LPVOID) -> BOOL;
pub type FnFindFirstStreamW =
    unsafe extern "system" fn(LPCWSTR, STREAM_INFO_LEVELS, LPVOID, DWORD) -> HANDLE;
pub type FnFindFirstVolumeW = unsafe extern "system" fn(LPWSTR, DWORD) -> HANDLE;
pub type FnFindNLSString =
    unsafe extern "system" fn(LCID, DWORD, LPCWSTR, c_int, LPCWSTR, c_int, LPINT) -> c_int;
pub type FnFindNLSStringEx = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    LPCWSTR,
    c_int,
    LPCWSTR,
    c_int,
    LPINT,
    LPNLSVERSIONINFO,
    LPVOID,
    LPARAM,
) -> c_int;
pub type FnFindNextChangeNotification = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFindNextFileA = unsafe extern "system" fn(HANDLE, LPWIN32_FIND_DATAA) -> BOOL;
pub type FnFindNextFileNameW = unsafe extern "system" fn(HANDLE, LPDWORD, PWSTR) -> BOOL;
pub type FnFindNextFileW = unsafe extern "system" fn(HANDLE, LPWIN32_FIND_DATAW) -> BOOL;
pub type FnFindNextStreamW = unsafe extern "system" fn(HANDLE, LPVOID) -> BOOL;
pub type FnFindNextVolumeW = unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> BOOL;
pub type FnFindResourceExW = unsafe extern "system" fn(HMODULE, LPCWSTR, LPCWSTR, WORD) -> HRSRC;
pub type FnFindResourceW = unsafe extern "system" fn(HMODULE, LPCWSTR, LPCWSTR) -> HRSRC;
pub type FnFindStringOrdinal =
    unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPCWSTR, c_int, BOOL) -> c_int;
pub type FnFindVolumeClose = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlsAlloc = unsafe extern "system" fn(PFLS_CALLBACK_FUNCTION) -> DWORD;
pub type FnFlsFree = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnFlsGetValue = unsafe extern "system" fn(DWORD) -> PVOID;
pub type FnFlsSetValue = unsafe extern "system" fn(DWORD, PVOID) -> BOOL;
pub type FnFlushConsoleInputBuffer = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlushFileBuffers = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlushInstructionCache = unsafe extern "system" fn(HANDLE, LPCVOID, SIZE_T) -> BOOL;
pub type FnFlushProcessWriteBuffers = unsafe extern "system" fn() -> ();
pub type FnFlushViewOfFile = unsafe extern "system" fn(LPCVOID, SIZE_T) -> BOOL;
pub type FnFoldStringW = unsafe extern "system" fn(DWORD, LPCWCH, c_int, LPWSTR, c_int) -> c_int;
pub type FnFormatMessageA =
    unsafe extern "system" fn(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, *mut va_list) -> DWORD;
pub type FnFormatMessageW =
    unsafe extern "system" fn(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, *mut va_list) -> DWORD;
pub type FnFreeConsole = unsafe extern "system" fn() -> BOOL;
pub type FnFreeEnvironmentStringsA = unsafe extern "system" fn(LPCH) -> BOOL;
pub type FnFreeEnvironmentStringsW = unsafe extern "system" fn(LPWCH) -> BOOL;
pub type FnFreeLibrary = unsafe extern "system" fn(HMODULE) -> BOOL;
pub type FnFreeLibraryAndExitThread = unsafe extern "system" fn(HMODULE, DWORD) -> ();
pub type FnFreeLibraryWhenCallbackReturns =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HMODULE) -> ();
pub type FnFreeResource = unsafe extern "system" fn(HGLOBAL) -> BOOL;
pub type FnFreeSid = unsafe extern "system" fn(PSID) -> PVOID;
pub type FnFreeUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnGenerateConsoleCtrlEvent = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnGetACP = unsafe extern "system" fn() -> UINT;
pub type FnGetAce = unsafe extern "system" fn(PACL, DWORD, *mut LPVOID) -> BOOL;
pub type FnGetAclInformation =
    unsafe extern "system" fn(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS) -> BOOL;
pub type FnGetAppContainerAce =
    unsafe extern "system" fn(PACL, DWORD, *mut PVOID, *mut DWORD) -> BOOL;
pub type FnGetAppContainerNamedObjectPath =
    unsafe extern "system" fn(HANDLE, PSID, ULONG, LPWSTR, PULONG) -> BOOL;
pub type FnGetApplicationRecoveryCallback = unsafe extern "system" fn(
    HANDLE,
    *mut APPLICATION_RECOVERY_CALLBACK,
    *mut PVOID,
    PDWORD,
    PDWORD,
) -> HRESULT;
pub type FnGetApplicationRestartSettings =
    unsafe extern "system" fn(HANDLE, PWSTR, PDWORD, PDWORD) -> HRESULT;
pub type FnGetCPInfo = unsafe extern "system" fn(UINT, LPCPINFO) -> BOOL;
pub type FnGetCPInfoExW = unsafe extern "system" fn(UINT, DWORD, LPCPINFOEXW) -> BOOL;
pub type FnGetCachedSigningLevel =
    unsafe extern "system" fn(HANDLE, PULONG, PULONG, PUCHAR, PULONG, PULONG) -> BOOL;
pub type FnGetCalendarInfoEx =
    unsafe extern "system" fn(LPCWSTR, CALID, LPCWSTR, CALTYPE, LPWSTR, c_int, LPDWORD) -> c_int;
pub type FnGetCalendarInfoW =
    unsafe extern "system" fn(LCID, CALID, CALTYPE, LPWSTR, c_int, LPDWORD) -> c_int;
pub type FnGetCommConfig = unsafe extern "system" fn(HANDLE, LPCOMMCONFIG, LPDWORD) -> BOOL;
pub type FnGetCommMask = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetCommModemStatus = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetCommProperties = unsafe extern "system" fn(HANDLE, LPCOMMPROP) -> BOOL;
pub type FnGetCommState = unsafe extern "system" fn(HANDLE, LPDCB) -> BOOL;
pub type FnGetCommTimeouts = unsafe extern "system" fn(HANDLE, LPCOMMTIMEOUTS) -> BOOL;
pub type FnGetCommandLineA = unsafe extern "system" fn() -> LPSTR;
pub type FnGetCommandLineW = unsafe extern "system" fn() -> LPWSTR;
pub type FnGetCompressedFileSizeA = unsafe extern "system" fn(LPCSTR, LPDWORD) -> DWORD;
pub type FnGetCompressedFileSizeW = unsafe extern "system" fn(LPCWSTR, LPDWORD) -> DWORD;
pub type FnGetComputerNameExA =
    unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD) -> BOOL;
pub type FnGetComputerNameExW =
    unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD) -> BOOL;
pub type FnGetConsoleAliasA = unsafe extern "system" fn(LPSTR, LPSTR, DWORD, LPSTR) -> DWORD;
pub type FnGetConsoleAliasExesA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnGetConsoleAliasExesLengthA = unsafe extern "system" fn() -> DWORD;
pub type FnGetConsoleAliasExesLengthW = unsafe extern "system" fn() -> DWORD;
pub type FnGetConsoleAliasExesW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnGetConsoleAliasW = unsafe extern "system" fn(LPWSTR, LPWSTR, DWORD, LPWSTR) -> DWORD;
pub type FnGetConsoleAliasesA = unsafe extern "system" fn(LPSTR, DWORD, LPSTR) -> DWORD;
pub type FnGetConsoleAliasesLengthA = unsafe extern "system" fn(LPSTR) -> DWORD;
pub type FnGetConsoleAliasesLengthW = unsafe extern "system" fn(LPWSTR) -> DWORD;
pub type FnGetConsoleAliasesW = unsafe extern "system" fn(LPWSTR, DWORD, LPWSTR) -> DWORD;
pub type FnGetConsoleCP = unsafe extern "system" fn() -> UINT;
pub type FnGetConsoleCursorInfo = unsafe extern "system" fn(HANDLE, PCONSOLE_CURSOR_INFO) -> BOOL;
pub type FnGetConsoleDisplayMode = unsafe extern "system" fn(LPDWORD) -> BOOL;
pub type FnGetConsoleFontSize = unsafe extern "system" fn(HANDLE, DWORD) -> COORD;
pub type FnGetConsoleHistoryInfo = unsafe extern "system" fn(PCONSOLE_HISTORY_INFO) -> BOOL;
pub type FnGetConsoleMode = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetConsoleOriginalTitleA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnGetConsoleOriginalTitleW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnGetConsoleOutputCP = unsafe extern "system" fn() -> UINT;
pub type FnGetConsoleProcessList = unsafe extern "system" fn(LPDWORD, DWORD) -> DWORD;
pub type FnGetConsoleScreenBufferInfo =
    unsafe extern "system" fn(HANDLE, PCONSOLE_SCREEN_BUFFER_INFO) -> BOOL;
pub type FnGetConsoleScreenBufferInfoEx =
    unsafe extern "system" fn(HANDLE, PCONSOLE_SCREEN_BUFFER_INFOEX) -> BOOL;
pub type FnGetConsoleSelectionInfo = unsafe extern "system" fn(PCONSOLE_SELECTION_INFO) -> BOOL;
pub type FnGetConsoleTitleA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnGetConsoleTitleW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnGetConsoleWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetCurrencyFormatEx =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPCWSTR, *const CURRENCYFMTW, LPWSTR, c_int) -> c_int;
pub type FnGetCurrencyFormatW =
    unsafe extern "system" fn(LCID, DWORD, LPCWSTR, *const CURRENCYFMTW, LPWSTR, c_int) -> c_int;
pub type FnGetCurrentActCtx = unsafe extern "system" fn(*mut HANDLE) -> BOOL;
pub type FnGetCurrentConsoleFont =
    unsafe extern "system" fn(HANDLE, BOOL, PCONSOLE_FONT_INFO) -> BOOL;
pub type FnGetCurrentConsoleFontEx =
    unsafe extern "system" fn(HANDLE, BOOL, PCONSOLE_FONT_INFOEX) -> BOOL;
pub type FnGetCurrentDirectoryA = unsafe extern "system" fn(DWORD, LPSTR) -> DWORD;
pub type FnGetCurrentDirectoryW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;
pub type FnGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
pub type FnGetCurrentProcessId = unsafe extern "system" fn() -> DWORD;
pub type FnGetCurrentProcessorNumber = unsafe extern "system" fn() -> DWORD;
pub type FnGetCurrentProcessorNumberEx = unsafe extern "system" fn(PPROCESSOR_NUMBER) -> ();
pub type FnGetCurrentThread = unsafe extern "system" fn() -> HANDLE;
pub type FnGetCurrentThreadId = unsafe extern "system" fn() -> DWORD;
pub type FnGetCurrentThreadStackLimits = unsafe extern "system" fn(PULONG_PTR, PULONG_PTR) -> ();
pub type FnGetDateFormatA =
    unsafe extern "system" fn(LCID, DWORD, *const SYSTEMTIME, LPCSTR, LPSTR, c_int) -> c_int;
pub type FnGetDateFormatEx = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    *const SYSTEMTIME,
    LPCWSTR,
    LPWSTR,
    c_int,
    LPCWSTR,
) -> c_int;
pub type FnGetDateFormatW =
    unsafe extern "system" fn(LCID, DWORD, *const SYSTEMTIME, LPCWSTR, LPWSTR, c_int) -> c_int;
pub type FnGetDeviceDriverBaseNameA = unsafe extern "system" fn(LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnGetDeviceDriverBaseNameW = unsafe extern "system" fn(LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnGetDeviceDriverFileNameA = unsafe extern "system" fn(LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnGetDeviceDriverFileNameW = unsafe extern "system" fn(LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnGetDiskFreeSpaceA =
    unsafe extern "system" fn(LPCSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetDiskFreeSpaceExA =
    unsafe extern "system" fn(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER) -> BOOL;
pub type FnGetDiskFreeSpaceExW =
    unsafe extern "system" fn(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER) -> BOOL;
pub type FnGetDiskFreeSpaceW =
    unsafe extern "system" fn(LPCWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetDriveTypeA = unsafe extern "system" fn(LPCSTR) -> UINT;
pub type FnGetDriveTypeW = unsafe extern "system" fn(LPCWSTR) -> UINT;
pub type FnGetDurationFormatEx = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    *const SYSTEMTIME,
    ULONGLONG,
    LPCWSTR,
    LPWSTR,
    c_int,
) -> c_int;
pub type FnGetDynamicTimeZoneInformation =
    unsafe extern "system" fn(PDYNAMIC_TIME_ZONE_INFORMATION) -> DWORD;
pub type FnGetDynamicTimeZoneInformationEffectiveYears =
    unsafe extern "system" fn(PDYNAMIC_TIME_ZONE_INFORMATION, LPDWORD, LPDWORD) -> DWORD;
pub type FnGetEnvironmentStrings = unsafe extern "system" fn() -> LPCH;
pub type FnGetEnvironmentStringsW = unsafe extern "system" fn() -> LPWCH;
pub type FnGetEnvironmentVariableA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnGetEnvironmentVariableW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetErrorMode = unsafe extern "system" fn() -> UINT;
pub type FnGetExitCodeProcess = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetExitCodeThread = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetFileAttributesA = unsafe extern "system" fn(LPCSTR) -> DWORD;
pub type FnGetFileAttributesExA =
    unsafe extern "system" fn(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID) -> BOOL;
pub type FnGetFileAttributesExW =
    unsafe extern "system" fn(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID) -> BOOL;
pub type FnGetFileAttributesW = unsafe extern "system" fn(LPCWSTR) -> DWORD;
pub type FnGetFileInformationByHandle =
    unsafe extern "system" fn(HANDLE, LPBY_HANDLE_FILE_INFORMATION) -> BOOL;
pub type FnGetFileInformationByHandleEx =
    unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnGetFileMUIInfo =
    unsafe extern "system" fn(DWORD, PCWSTR, PFILEMUIINFO, *mut DWORD) -> BOOL;
pub type FnGetFileMUIPath =
    unsafe extern "system" fn(DWORD, PCWSTR, PWSTR, PULONG, PWSTR, PULONG, PULONGLONG) -> BOOL;
pub type FnGetFileSecurityW = unsafe extern "system" fn(
    LPCWSTR,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnGetFileSize = unsafe extern "system" fn(HANDLE, LPDWORD) -> DWORD;
pub type FnGetFileSizeEx = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> BOOL;
pub type FnGetFileTime =
    unsafe extern "system" fn(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetFileType = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetFileVersionInfoA =
    unsafe extern "system" fn(LPCSTR, DWORD, DWORD, *mut c_void) -> BOOL;
pub type FnGetFileVersionInfoSizeA = unsafe extern "system" fn(LPCSTR, *mut DWORD) -> DWORD;
pub type FnGetFileVersionInfoSizeW = unsafe extern "system" fn(LPCWSTR, *mut DWORD) -> DWORD;
pub type FnGetFileVersionInfoW =
    unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, *mut c_void) -> BOOL;
pub type FnGetFinalPathNameByHandleA =
    unsafe extern "system" fn(HANDLE, LPSTR, DWORD, DWORD) -> DWORD;
pub type FnGetFinalPathNameByHandleW =
    unsafe extern "system" fn(HANDLE, LPWSTR, DWORD, DWORD) -> DWORD;
pub type FnGetFullPathNameA = unsafe extern "system" fn(LPCSTR, DWORD, LPSTR, *mut LPSTR) -> DWORD;
pub type FnGetFullPathNameW =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPWSTR, *mut LPWSTR) -> DWORD;
pub type FnGetGeoInfoW = unsafe extern "system" fn(GEOID, GEOTYPE, LPWSTR, c_int, LANGID) -> c_int;
pub type FnGetHandleInformation = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetKernelObjectSecurity = unsafe extern "system" fn(
    HANDLE,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnGetLargePageMinimum = unsafe extern "system" fn() -> SIZE_T;
pub type FnGetLargestConsoleWindowSize = unsafe extern "system" fn(HANDLE) -> COORD;
pub type FnGetLastError = unsafe extern "system" fn() -> DWORD;
pub type FnGetLengthSid = unsafe extern "system" fn(PSID) -> DWORD;
pub type FnGetLocalTime = unsafe extern "system" fn(LPSYSTEMTIME) -> ();
pub type FnGetLocaleInfoA = unsafe extern "system" fn(LCID, LCTYPE, LPSTR, c_int) -> c_int;
pub type FnGetLocaleInfoEx = unsafe extern "system" fn(LPCWSTR, LCTYPE, LPWSTR, c_int) -> c_int;
pub type FnGetLocaleInfoW = unsafe extern "system" fn(LCID, LCTYPE, LPWSTR, c_int) -> c_int;
pub type FnGetLogicalDriveStringsW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;
pub type FnGetLogicalDrives = unsafe extern "system" fn() -> DWORD;
pub type FnGetLogicalProcessorInformation =
    unsafe extern "system" fn(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD) -> BOOL;
pub type FnGetLogicalProcessorInformationEx = unsafe extern "system" fn(
    LOGICAL_PROCESSOR_RELATIONSHIP,
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    PDWORD,
) -> BOOL;
pub type FnGetLongPathNameA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnGetLongPathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetMappedFileNameA = unsafe extern "system" fn(HANDLE, LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnGetMappedFileNameW = unsafe extern "system" fn(HANDLE, LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnGetMemoryErrorHandlingCapabilities = unsafe extern "system" fn(PULONG) -> BOOL;
pub type FnGetModuleBaseNameA = unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnGetModuleBaseNameW = unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnGetModuleFileNameA = unsafe extern "system" fn(HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnGetModuleFileNameExA = unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnGetModuleFileNameExW =
    unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnGetModuleFileNameW = unsafe extern "system" fn(HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnGetModuleHandleA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
pub type FnGetModuleHandleExA = unsafe extern "system" fn(DWORD, LPCSTR, *mut HMODULE) -> BOOL;
pub type FnGetModuleHandleExW = unsafe extern "system" fn(DWORD, LPCWSTR, *mut HMODULE) -> BOOL;
pub type FnGetModuleHandleW = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
pub type FnGetModuleInformation =
    unsafe extern "system" fn(HANDLE, HMODULE, LPMODULEINFO, DWORD) -> BOOL;
pub type FnGetNLSVersion = unsafe extern "system" fn(NLS_FUNCTION, LCID, LPNLSVERSIONINFO) -> BOOL;
pub type FnGetNLSVersionEx =
    unsafe extern "system" fn(NLS_FUNCTION, LPCWSTR, LPNLSVERSIONINFOEX) -> BOOL;
pub type FnGetNamedPipeClientComputerNameW =
    unsafe extern "system" fn(HANDLE, LPWSTR, ULONG) -> BOOL;
pub type FnGetNamedPipeHandleStateW =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD) -> BOOL;
pub type FnGetNamedPipeInfo =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetNativeSystemInfo = unsafe extern "system" fn(LPSYSTEM_INFO) -> ();
pub type FnGetNumaHighestNodeNumber = unsafe extern "system" fn(PULONG) -> BOOL;
pub type FnGetNumaNodeProcessorMaskEx = unsafe extern "system" fn(USHORT, PGROUP_AFFINITY) -> BOOL;
pub type FnGetNumaProximityNodeEx = unsafe extern "system" fn(ULONG, PUSHORT) -> BOOL;
pub type FnGetNumberFormatEx =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPCWSTR, *const NUMBERFMTW, LPWSTR, c_int) -> c_int;
pub type FnGetNumberFormatW =
    unsafe extern "system" fn(LCID, DWORD, LPCWSTR, *const NUMBERFMTW, LPWSTR, c_int) -> c_int;
pub type FnGetNumberOfConsoleInputEvents = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetNumberOfConsoleMouseButtons = unsafe extern "system" fn(LPDWORD) -> BOOL;
pub type FnGetOEMCP = unsafe extern "system" fn() -> UINT;
pub type FnGetOverlappedResult =
    unsafe extern "system" fn(HANDLE, LPOVERLAPPED, LPDWORD, BOOL) -> BOOL;
pub type FnGetOverlappedResultEx =
    unsafe extern "system" fn(HANDLE, LPOVERLAPPED, LPDWORD, DWORD, BOOL) -> BOOL;
pub type FnGetPerformanceInfo = unsafe extern "system" fn(PPERFORMANCE_INFORMATION, DWORD) -> BOOL;
pub type FnGetPhysicallyInstalledSystemMemory = unsafe extern "system" fn(PULONGLONG) -> BOOL;
pub type FnGetPriorityClass = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetPrivateObjectSecurity = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    PDWORD,
) -> BOOL;
pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;
pub type FnGetProcessGroupAffinity = unsafe extern "system" fn(HANDLE, PUSHORT, PUSHORT) -> BOOL;
pub type FnGetProcessHandleCount = unsafe extern "system" fn(HANDLE, PDWORD) -> BOOL;
pub type FnGetProcessHeap = unsafe extern "system" fn() -> HANDLE;
pub type FnGetProcessHeaps = unsafe extern "system" fn(DWORD, PHANDLE) -> DWORD;
pub type FnGetProcessId = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetProcessIdOfThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetProcessImageFileNameA = unsafe extern "system" fn(HANDLE, LPSTR, DWORD) -> DWORD;
pub type FnGetProcessImageFileNameW = unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> DWORD;
pub type FnGetProcessInformation =
    unsafe extern "system" fn(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnGetProcessMemoryInfo =
    unsafe extern "system" fn(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD) -> BOOL;
pub type FnGetProcessMitigationPolicy =
    unsafe extern "system" fn(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T) -> BOOL;
pub type FnGetProcessPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PULONG, PZZWSTR, PULONG) -> BOOL;
pub type FnGetProcessPriorityBoost = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnGetProcessShutdownParameters = unsafe extern "system" fn(LPDWORD, LPDWORD) -> BOOL;
pub type FnGetProcessTimes =
    unsafe extern "system" fn(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetProcessVersion = unsafe extern "system" fn(DWORD) -> DWORD;
pub type FnGetProcessWorkingSetSize = unsafe extern "system" fn(HANDLE, PSIZE_T, PSIZE_T) -> BOOL;
pub type FnGetProcessWorkingSetSizeEx =
    unsafe extern "system" fn(HANDLE, PSIZE_T, PSIZE_T, PDWORD) -> BOOL;
pub type FnGetProcessorSystemCycleTime =
    unsafe extern "system" fn(USHORT, PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, PDWORD) -> BOOL;
pub type FnGetProductInfo = unsafe extern "system" fn(DWORD, DWORD, DWORD, DWORD, PDWORD) -> BOOL;
pub type FnGetQueuedCompletionStatus =
    unsafe extern "system" fn(HANDLE, LPDWORD, PULONG_PTR, *mut LPOVERLAPPED, DWORD) -> BOOL;
pub type FnGetQueuedCompletionStatusEx =
    unsafe extern "system" fn(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL) -> BOOL;
pub type FnGetSecurityDescriptorControl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, LPDWORD) -> BOOL;
pub type FnGetSecurityDescriptorDacl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, LPBOOL, *mut PACL, LPBOOL) -> BOOL;
pub type FnGetSecurityDescriptorGroup =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, *mut PSID, LPBOOL) -> BOOL;
pub type FnGetSecurityDescriptorLength = unsafe extern "system" fn(PSECURITY_DESCRIPTOR) -> DWORD;
pub type FnGetSecurityDescriptorOwner =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, *mut PSID, LPBOOL) -> BOOL;
pub type FnGetSecurityDescriptorRMControl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PUCHAR) -> DWORD;
pub type FnGetSecurityDescriptorSacl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, LPBOOL, *mut PACL, LPBOOL) -> BOOL;
pub type FnGetShortPathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetSidIdentifierAuthority = unsafe extern "system" fn(PSID) -> PSID_IDENTIFIER_AUTHORITY;
pub type FnGetSidLengthRequired = unsafe extern "system" fn(UCHAR) -> DWORD;
pub type FnGetSidSubAuthority = unsafe extern "system" fn(PSID, DWORD) -> PDWORD;
pub type FnGetSidSubAuthorityCount = unsafe extern "system" fn(PSID) -> PUCHAR;
pub type FnGetStartupInfoW = unsafe extern "system" fn(LPSTARTUPINFOW) -> ();
pub type FnGetStdHandle = unsafe extern "system" fn(DWORD) -> HANDLE;
pub type FnGetStringScripts =
    unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnGetStringTypeA = unsafe extern "system" fn(LCID, DWORD, LPCSTR, c_int, LPWORD) -> BOOL;
pub type FnGetStringTypeExW = unsafe extern "system" fn(LCID, DWORD, LPCWCH, c_int, LPWORD) -> BOOL;
pub type FnGetStringTypeW = unsafe extern "system" fn(DWORD, LPCWCH, c_int, LPWORD) -> BOOL;
pub type FnGetSystemDefaultLCID = unsafe extern "system" fn() -> LCID;
pub type FnGetSystemDefaultLangID = unsafe extern "system" fn() -> LANGID;
pub type FnGetSystemDefaultLocaleName = unsafe extern "system" fn(LPWSTR, c_int) -> c_int;
pub type FnGetSystemDefaultUILanguage = unsafe extern "system" fn() -> LANGID;
pub type FnGetSystemDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetSystemFileCacheSize = unsafe extern "system" fn(PSIZE_T, PSIZE_T, PDWORD) -> BOOL;
pub type FnGetSystemFirmwareTable = unsafe extern "system" fn(DWORD, DWORD, PVOID, DWORD) -> UINT;
pub type FnGetSystemInfo = unsafe extern "system" fn(LPSYSTEM_INFO) -> ();
pub type FnGetSystemPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PULONG, PZZWSTR, PULONG) -> BOOL;
pub type FnGetSystemTime = unsafe extern "system" fn(LPSYSTEMTIME) -> ();
pub type FnGetSystemTimeAdjustment = unsafe extern "system" fn(PDWORD, PDWORD, PBOOL) -> BOOL;
pub type FnGetSystemTimeAsFileTime = unsafe extern "system" fn(LPFILETIME) -> ();
pub type FnGetSystemTimePreciseAsFileTime = unsafe extern "system" fn(LPFILETIME) -> ();
pub type FnGetSystemTimes = unsafe extern "system" fn(LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetSystemWindowsDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemWindowsDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetSystemWow64DirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemWow64DirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetTempFileNameA = unsafe extern "system" fn(LPCSTR, LPCSTR, UINT, LPSTR) -> UINT;
pub type FnGetTempFileNameW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, UINT, LPWSTR) -> UINT;
pub type FnGetTempPathA = unsafe extern "system" fn(DWORD, LPSTR) -> DWORD;
pub type FnGetTempPathW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;
pub type FnGetThreadContext = unsafe extern "system" fn(HANDLE, LPCONTEXT) -> BOOL;
pub type FnGetThreadErrorMode = unsafe extern "system" fn() -> DWORD;
pub type FnGetThreadGroupAffinity = unsafe extern "system" fn(HANDLE, PGROUP_AFFINITY) -> BOOL;
pub type FnGetThreadIOPendingFlag = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnGetThreadId = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetThreadIdealProcessorEx = unsafe extern "system" fn(HANDLE, PPROCESSOR_NUMBER) -> BOOL;
pub type FnGetThreadInformation =
    unsafe extern "system" fn(HANDLE, THREAD_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnGetThreadLocale = unsafe extern "system" fn() -> LCID;
pub type FnGetThreadPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PULONG, PZZWSTR, PULONG) -> BOOL;
pub type FnGetThreadPriority = unsafe extern "system" fn(HANDLE) -> c_int;
pub type FnGetThreadPriorityBoost = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnGetThreadTimes =
    unsafe extern "system" fn(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetThreadUILanguage = unsafe extern "system" fn() -> LANGID;
pub type FnGetTickCount = unsafe extern "system" fn() -> DWORD;
pub type FnGetTickCount64 = unsafe extern "system" fn() -> ULONGLONG;
pub type FnGetTimeFormatA =
    unsafe extern "system" fn(LCID, DWORD, *const SYSTEMTIME, LPCSTR, LPSTR, c_int) -> c_int;
pub type FnGetTimeFormatEx =
    unsafe extern "system" fn(LPCWSTR, DWORD, *const SYSTEMTIME, LPCWSTR, LPWSTR, c_int) -> c_int;
pub type FnGetTimeFormatW =
    unsafe extern "system" fn(LCID, DWORD, *const SYSTEMTIME, LPCWSTR, LPWSTR, c_int) -> c_int;
pub type FnGetTimeZoneInformation = unsafe extern "system" fn(LPTIME_ZONE_INFORMATION) -> DWORD;
pub type FnGetTimeZoneInformationForYear = unsafe extern "system" fn(
    USHORT,
    PDYNAMIC_TIME_ZONE_INFORMATION,
    LPTIME_ZONE_INFORMATION,
) -> BOOL;
pub type FnGetTokenInformation =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD) -> BOOL;
pub type FnGetTraceEnableFlags = unsafe extern "system" fn(TRACEHANDLE) -> ULONG;
pub type FnGetTraceEnableLevel = unsafe extern "system" fn(TRACEHANDLE) -> UCHAR;
pub type FnGetTraceLoggerHandle = unsafe extern "system" fn(PVOID) -> TRACEHANDLE;
pub type FnGetUILanguageInfo =
    unsafe extern "system" fn(DWORD, PCZZWSTR, PZZWSTR, PDWORD, PDWORD) -> BOOL;
pub type FnGetUserDefaultLCID = unsafe extern "system" fn() -> LCID;
pub type FnGetUserDefaultLangID = unsafe extern "system" fn() -> LANGID;
pub type FnGetUserDefaultLocaleName = unsafe extern "system" fn(LPWSTR, c_int) -> c_int;
pub type FnGetUserDefaultUILanguage = unsafe extern "system" fn() -> LANGID;
pub type FnGetUserGeoID = unsafe extern "system" fn(GEOCLASS) -> GEOID;
pub type FnGetUserPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PULONG, PZZWSTR, PULONG) -> BOOL;
pub type FnGetVersion = unsafe extern "system" fn() -> DWORD;
pub type FnGetVersionExA = unsafe extern "system" fn(LPOSVERSIONINFOA) -> BOOL;
pub type FnGetVersionExW = unsafe extern "system" fn(LPOSVERSIONINFOW) -> BOOL;
pub type FnGetVolumeInformationA = unsafe extern "system" fn(
    LPCSTR,
    LPSTR,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPSTR,
    DWORD,
) -> BOOL;
pub type FnGetVolumeInformationByHandleW = unsafe extern "system" fn(
    HANDLE,
    LPWSTR,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPWSTR,
    DWORD,
) -> BOOL;
pub type FnGetVolumeInformationW = unsafe extern "system" fn(
    LPCWSTR,
    LPWSTR,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPWSTR,
    DWORD,
) -> BOOL;
pub type FnGetVolumeNameForVolumeMountPointW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> BOOL;
pub type FnGetVolumePathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> BOOL;
pub type FnGetVolumePathNamesForVolumeNameW =
    unsafe extern "system" fn(LPCWSTR, LPWCH, DWORD, PDWORD) -> BOOL;
pub type FnGetWindowsAccountDomainSid = unsafe extern "system" fn(PSID, PSID, *mut DWORD) -> BOOL;
pub type FnGetWindowsDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetWindowsDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetWriteWatch =
    unsafe extern "system" fn(DWORD, PVOID, SIZE_T, *mut PVOID, *mut ULONG_PTR, LPDWORD) -> UINT;
pub type FnGetWsChanges =
    unsafe extern "system" fn(HANDLE, PPSAPI_WS_WATCH_INFORMATION, DWORD) -> BOOL;
pub type FnGetWsChangesEx =
    unsafe extern "system" fn(HANDLE, PPSAPI_WS_WATCH_INFORMATION_EX, PDWORD) -> BOOL;
pub type FnGlobalAlloc = unsafe extern "system" fn(UINT, SIZE_T) -> HGLOBAL;
pub type FnGlobalFlags = unsafe extern "system" fn(HGLOBAL) -> UINT;
pub type FnGlobalFree = unsafe extern "system" fn(HGLOBAL) -> HGLOBAL;
pub type FnGlobalHandle = unsafe extern "system" fn(LPCVOID) -> HGLOBAL;
pub type FnGlobalLock = unsafe extern "system" fn(HGLOBAL) -> LPVOID;
pub type FnGlobalMemoryStatusEx = unsafe extern "system" fn(LPMEMORYSTATUSEX) -> BOOL;
pub type FnGlobalReAlloc = unsafe extern "system" fn(HGLOBAL, SIZE_T, UINT) -> HGLOBAL;
pub type FnGlobalSize = unsafe extern "system" fn(HGLOBAL) -> SIZE_T;
pub type FnGlobalUnlock = unsafe extern "system" fn(HGLOBAL) -> BOOL;
pub type FnHeapAlloc = unsafe extern "system" fn(HANDLE, DWORD, SIZE_T) -> LPVOID;
pub type FnHeapCompact = unsafe extern "system" fn(HANDLE, DWORD) -> SIZE_T;
pub type FnHeapCreate = unsafe extern "system" fn(DWORD, SIZE_T, SIZE_T) -> HANDLE;
pub type FnHeapDestroy = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnHeapFree = unsafe extern "system" fn(HANDLE, DWORD, LPVOID) -> BOOL;
pub type FnHeapLock = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnHeapQueryInformation =
    unsafe extern "system" fn(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T) -> BOOL;
pub type FnHeapReAlloc = unsafe extern "system" fn(HANDLE, DWORD, LPVOID, SIZE_T) -> LPVOID;
pub type FnHeapSetInformation =
    unsafe extern "system" fn(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T) -> BOOL;
pub type FnHeapSize = unsafe extern "system" fn(HANDLE, DWORD, LPCVOID) -> SIZE_T;
pub type FnHeapSummary = unsafe extern "system" fn(HANDLE, DWORD, LPHEAP_SUMMARY) -> BOOL;
pub type FnHeapUnlock = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnHeapValidate = unsafe extern "system" fn(HANDLE, DWORD, LPCVOID) -> BOOL;
pub type FnHeapWalk = unsafe extern "system" fn(HANDLE, LPPROCESS_HEAP_ENTRY) -> BOOL;
pub type FnImpersonateAnonymousToken = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateLoggedOnUser = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateNamedPipeClient = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateSelf = unsafe extern "system" fn(SECURITY_IMPERSONATION_LEVEL) -> BOOL;
pub type FnInitOnceBeginInitialize =
    unsafe extern "system" fn(LPINIT_ONCE, DWORD, PBOOL, *mut LPVOID) -> BOOL;
pub type FnInitOnceComplete = unsafe extern "system" fn(LPINIT_ONCE, DWORD, LPVOID) -> BOOL;
pub type FnInitOnceExecuteOnce =
    unsafe extern "system" fn(PINIT_ONCE, PINIT_ONCE_FN, PVOID, *mut LPVOID) -> BOOL;
pub type FnInitOnceInitialize = unsafe extern "system" fn(PINIT_ONCE) -> ();
pub type FnInitializeAcl = unsafe extern "system" fn(PACL, DWORD, DWORD) -> BOOL;
pub type FnInitializeConditionVariable = unsafe extern "system" fn(PCONDITION_VARIABLE) -> ();
pub type FnInitializeContext =
    unsafe extern "system" fn(PVOID, DWORD, *mut PCONTEXT, PDWORD) -> BOOL;
pub type FnInitializeCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnInitializeCriticalSectionAndSpinCount =
    unsafe extern "system" fn(LPCRITICAL_SECTION, DWORD) -> BOOL;
pub type FnInitializeCriticalSectionEx =
    unsafe extern "system" fn(LPCRITICAL_SECTION, DWORD, DWORD) -> BOOL;
pub type FnInitializeEnclave =
    unsafe extern "system" fn(HANDLE, LPVOID, LPCVOID, DWORD, LPDWORD) -> BOOL;
pub type FnInitializeProcThreadAttributeList =
    unsafe extern "system" fn(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T) -> BOOL;
pub type FnInitializeProcessForWsWatch = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnInitializeSListHead = unsafe extern "system" fn(PSLIST_HEADER) -> ();
pub type FnInitializeSRWLock = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnInitializeSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, DWORD) -> BOOL;
pub type FnInitializeSid = unsafe extern "system" fn(PSID, PSID_IDENTIFIER_AUTHORITY, BYTE) -> BOOL;
pub type FnInitializeSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER, LONG, LONG) -> BOOL;
pub type FnInstallELAMCertificateInfo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnInterlockedFlushSList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnInterlockedPopEntrySList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnInterlockedPushEntrySList =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY) -> PSLIST_ENTRY;
pub type FnInterlockedPushListSListEx =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, ULONG) -> PSLIST_ENTRY;
pub type FnInternetTimeFromSystemTimeA =
    unsafe extern "system" fn(*const SYSTEMTIME, DWORD, LPSTR, DWORD) -> BOOL;
pub type FnInternetTimeFromSystemTimeW =
    unsafe extern "system" fn(*const SYSTEMTIME, DWORD, LPWSTR, DWORD) -> BOOL;
pub type FnInternetTimeToSystemTimeA =
    unsafe extern "system" fn(LPCSTR, *mut SYSTEMTIME, DWORD) -> BOOL;
pub type FnInternetTimeToSystemTimeW =
    unsafe extern "system" fn(LPCWSTR, *mut SYSTEMTIME, DWORD) -> BOOL;
pub type FnIsCharAlphaA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharAlphaNumericA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharAlphaNumericW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharAlphaW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharLowerA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharLowerW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharUpperA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharUpperW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsDBCSLeadByte = unsafe extern "system" fn(BYTE) -> BOOL;
pub type FnIsDBCSLeadByteEx = unsafe extern "system" fn(UINT, BYTE) -> BOOL;
pub type FnIsDebuggerPresent = unsafe extern "system" fn() -> BOOL;
pub type FnIsEnclaveTypeSupported = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnIsNLSDefinedString =
    unsafe extern "system" fn(NLS_FUNCTION, DWORD, LPNLSVERSIONINFO, LPCWSTR, INT) -> BOOL;
pub type FnIsNormalizedString = unsafe extern "system" fn(NORM_FORM, LPCWSTR, c_int) -> BOOL;
pub type FnIsProcessCritical = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnIsProcessInJob = unsafe extern "system" fn(HANDLE, HANDLE, PBOOL) -> BOOL;
pub type FnIsProcessorFeaturePresent = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnIsThreadAFiber = unsafe extern "system" fn() -> BOOL;
pub type FnIsThreadpoolTimerSet = unsafe extern "system" fn(PTP_TIMER) -> BOOL;
pub type FnIsTokenRestricted = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnIsValidAcl = unsafe extern "system" fn(PACL) -> BOOL;
pub type FnIsValidCodePage = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnIsValidLanguageGroup = unsafe extern "system" fn(LGRPID, DWORD) -> BOOL;
pub type FnIsValidLocale = unsafe extern "system" fn(LCID, DWORD) -> BOOL;
pub type FnIsValidLocaleName = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnIsValidNLSVersion =
    unsafe extern "system" fn(NLS_FUNCTION, LPCWSTR, LPNLSVERSIONINFOEX) -> BOOL;
pub type FnIsValidSecurityDescriptor = unsafe extern "system" fn(PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnIsValidSid = unsafe extern "system" fn(PSID) -> BOOL;
pub type FnIsWellKnownSid = unsafe extern "system" fn(PSID, WELL_KNOWN_SID_TYPE) -> BOOL;
pub type FnIsWow64Process = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnIsWow64Process2 = unsafe extern "system" fn(HANDLE, PUSHORT, PUSHORT) -> BOOL;
pub type FnK32EmptyWorkingSet = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnK32EnumDeviceDrivers = unsafe extern "system" fn(*mut LPVOID, DWORD, LPDWORD) -> BOOL;
pub type FnK32EnumPageFilesA = unsafe extern "system" fn(PENUM_PAGE_FILE_CALLBACKA, LPVOID) -> BOOL;
pub type FnK32EnumPageFilesW = unsafe extern "system" fn(PENUM_PAGE_FILE_CALLBACKW, LPVOID) -> BOOL;
pub type FnK32EnumProcessModules =
    unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, LPDWORD) -> BOOL;
pub type FnK32EnumProcessModulesEx =
    unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, LPDWORD, DWORD) -> BOOL;
pub type FnK32EnumProcesses = unsafe extern "system" fn(*mut DWORD, DWORD, LPDWORD) -> BOOL;
pub type FnK32GetDeviceDriverBaseNameA = unsafe extern "system" fn(LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnK32GetDeviceDriverBaseNameW = unsafe extern "system" fn(LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetDeviceDriverFileNameA = unsafe extern "system" fn(LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnK32GetDeviceDriverFileNameW = unsafe extern "system" fn(LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetMappedFileNameA = unsafe extern "system" fn(HANDLE, LPVOID, LPSTR, DWORD) -> DWORD;
pub type FnK32GetMappedFileNameW =
    unsafe extern "system" fn(HANDLE, LPVOID, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetModuleBaseNameA =
    unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnK32GetModuleBaseNameW =
    unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetModuleFileNameExA =
    unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnK32GetModuleFileNameExW =
    unsafe extern "system" fn(HANDLE, HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetModuleInformation =
    unsafe extern "system" fn(HANDLE, HMODULE, LPMODULEINFO, DWORD) -> BOOL;
pub type FnK32GetPerformanceInfo =
    unsafe extern "system" fn(PPERFORMANCE_INFORMATION, DWORD) -> BOOL;
pub type FnK32GetProcessImageFileNameA = unsafe extern "system" fn(HANDLE, LPSTR, DWORD) -> DWORD;
pub type FnK32GetProcessImageFileNameW = unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> DWORD;
pub type FnK32GetProcessMemoryInfo =
    unsafe extern "system" fn(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD) -> BOOL;
pub type FnK32GetWsChanges =
    unsafe extern "system" fn(HANDLE, PPSAPI_WS_WATCH_INFORMATION, DWORD) -> BOOL;
pub type FnK32GetWsChangesEx =
    unsafe extern "system" fn(HANDLE, PPSAPI_WS_WATCH_INFORMATION_EX, PDWORD) -> BOOL;
pub type FnK32InitializeProcessForWsWatch = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnK32QueryWorkingSet = unsafe extern "system" fn(HANDLE, PVOID, DWORD) -> BOOL;
pub type FnK32QueryWorkingSetEx = unsafe extern "system" fn(HANDLE, PVOID, DWORD) -> BOOL;
pub type FnLCIDToLocaleName = unsafe extern "system" fn(LCID, LPWSTR, c_int, DWORD) -> c_int;
pub type FnLCMapStringA =
    unsafe extern "system" fn(LCID, DWORD, LPCSTR, c_int, LPSTR, c_int) -> c_int;
pub type FnLCMapStringEx = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    LPCWSTR,
    c_int,
    LPWSTR,
    c_int,
    LPNLSVERSIONINFO,
    LPVOID,
    LPARAM,
) -> c_int;
pub type FnLCMapStringW =
    unsafe extern "system" fn(LCID, DWORD, LPCWSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnLeaveCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnLeaveCriticalSectionWhenCallbackReturns =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PCRITICAL_SECTION) -> ();
pub type FnLoadEnclaveData = unsafe extern "system" fn(
    HANDLE,
    LPVOID,
    LPCVOID,
    SIZE_T,
    DWORD,
    LPCVOID,
    DWORD,
    PSIZE_T,
    LPDWORD,
) -> BOOL;
pub type FnLoadEnclaveImageA = unsafe extern "system" fn(LPVOID, LPCSTR) -> BOOL;
pub type FnLoadEnclaveImageW = unsafe extern "system" fn(LPVOID, LPCWSTR) -> BOOL;
pub type FnLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
pub type FnLoadLibraryExA = unsafe extern "system" fn(LPCSTR, HANDLE, DWORD) -> HMODULE;
pub type FnLoadLibraryExW = unsafe extern "system" fn(LPCWSTR, HANDLE, DWORD) -> HMODULE;
pub type FnLoadLibraryW = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
pub type FnLoadPackagedLibrary = unsafe extern "system" fn(LPCWSTR, DWORD) -> HMODULE;
pub type FnLoadResource = unsafe extern "system" fn(HMODULE, HRSRC) -> HGLOBAL;
pub type FnLoadStringA = unsafe extern "system" fn(HINSTANCE, UINT, LPSTR, c_int) -> c_int;
pub type FnLoadStringW = unsafe extern "system" fn(HINSTANCE, UINT, LPWSTR, c_int) -> c_int;
pub type FnLocalAlloc = unsafe extern "system" fn(UINT, SIZE_T) -> HLOCAL;
pub type FnLocalFileTimeToFileTime = unsafe extern "system" fn(*const FILETIME, LPFILETIME) -> BOOL;
pub type FnLocalFlags = unsafe extern "system" fn(HLOCAL) -> UINT;
pub type FnLocalFree = unsafe extern "system" fn(HLOCAL) -> HLOCAL;
pub type FnLocalLock = unsafe extern "system" fn(HLOCAL) -> LPVOID;
pub type FnLocalReAlloc = unsafe extern "system" fn(HLOCAL, SIZE_T, UINT) -> HLOCAL;
pub type FnLocalSize = unsafe extern "system" fn(HLOCAL) -> SIZE_T;
pub type FnLocalUnlock = unsafe extern "system" fn(HLOCAL) -> BOOL;
pub type FnLocaleNameToLCID = unsafe extern "system" fn(LPCWSTR, DWORD) -> LCID;
pub type FnLockFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD) -> BOOL;
pub type FnLockFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED) -> BOOL;
pub type FnLockResource = unsafe extern "system" fn(HGLOBAL) -> LPVOID;
pub type FnMakeAbsoluteSD = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    LPDWORD,
    PACL,
    LPDWORD,
    PACL,
    LPDWORD,
    PSID,
    LPDWORD,
    PSID,
    LPDWORD,
) -> BOOL;
pub type FnMakeSelfRelativeSD =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, LPDWORD) -> BOOL;
pub type FnMapGenericMask = unsafe extern "system" fn(PDWORD, PGENERIC_MAPPING) -> ();
pub type FnMapUserPhysicalPages = unsafe extern "system" fn(PVOID, ULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnMapViewOfFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T) -> LPVOID;
pub type FnMapViewOfFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID) -> LPVOID;
pub type FnMapViewOfFileExNuma =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID, DWORD) -> LPVOID;
pub type FnMapViewOfFileFromApp =
    unsafe extern "system" fn(HANDLE, ULONG, ULONG64, SIZE_T) -> PVOID;
pub type FnMoveFileExW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD) -> BOOL;
pub type FnMoveFileWithProgressW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD) -> BOOL;
pub type FnMulDiv = unsafe extern "system" fn(c_int, c_int, c_int) -> c_int;
pub type FnMultiByteToWideChar =
    unsafe extern "system" fn(UINT, DWORD, LPCSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnNeedCurrentDirectoryForExePathA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnNeedCurrentDirectoryForExePathW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnNormalizeString =
    unsafe extern "system" fn(NORM_FORM, LPCWSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnObjectCloseAuditAlarmW = unsafe extern "system" fn(LPCWSTR, LPVOID, BOOL) -> BOOL;
pub type FnObjectDeleteAuditAlarmW = unsafe extern "system" fn(LPCWSTR, LPVOID, BOOL) -> BOOL;
pub type FnObjectOpenAuditAlarmW = unsafe extern "system" fn(
    LPCWSTR,
    LPVOID,
    LPWSTR,
    LPWSTR,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    DWORD,
    DWORD,
    PPRIVILEGE_SET,
    BOOL,
    BOOL,
    LPBOOL,
) -> BOOL;
pub type FnObjectPrivilegeAuditAlarmW =
    unsafe extern "system" fn(LPCWSTR, LPVOID, HANDLE, DWORD, PPRIVILEGE_SET, BOOL) -> BOOL;
pub type FnOfferVirtualMemory = unsafe extern "system" fn(PVOID, SIZE_T, OFFER_PRIORITY) -> DWORD;
pub type FnOpenEventA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenEventW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenFileById = unsafe extern "system" fn(
    HANDLE,
    LPFILE_ID_DESCRIPTOR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
) -> HANDLE;
pub type FnOpenFileMappingFromApp = unsafe extern "system" fn(ULONG, BOOL, PCWSTR) -> HANDLE;
pub type FnOpenFileMappingW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenMutexW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenPrivateNamespaceW = unsafe extern "system" fn(LPVOID, LPCWSTR) -> HANDLE;
pub type FnOpenProcess = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
pub type FnOpenProcessToken = unsafe extern "system" fn(HANDLE, DWORD, PHANDLE) -> BOOL;
pub type FnOpenSemaphoreW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenThread = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
pub type FnOpenThreadToken = unsafe extern "system" fn(HANDLE, DWORD, BOOL, PHANDLE) -> BOOL;
pub type FnOpenWaitableTimerW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOutputDebugStringA = unsafe extern "system" fn(LPCSTR) -> ();
pub type FnOutputDebugStringW = unsafe extern "system" fn(LPCWSTR) -> ();
pub type FnPeekConsoleInputA =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnPeekConsoleInputW =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnPeekNamedPipe =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnPerfCreateInstance =
    unsafe extern "system" fn(HANDLE, LPCGUID, PCWSTR, ULONG) -> PPERF_COUNTERSET_INSTANCE;
pub type FnPerfDecrementULongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG) -> ULONG;
pub type FnPerfDecrementULongLongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG) -> ULONG;
pub type FnPerfDeleteInstance =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE) -> ULONG;
pub type FnPerfIncrementULongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG) -> ULONG;
pub type FnPerfIncrementULongLongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG) -> ULONG;
pub type FnPerfQueryInstance =
    unsafe extern "system" fn(HANDLE, LPCGUID, LPCWSTR, ULONG) -> PPERF_COUNTERSET_INSTANCE;
pub type FnPerfSetCounterRefValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, PVOID) -> ULONG;
pub type FnPerfSetCounterSetInfo =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INFO, ULONG) -> ULONG;
pub type FnPerfSetULongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG) -> ULONG;
pub type FnPerfSetULongLongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG) -> ULONG;
pub type FnPerfStartProvider = unsafe extern "system" fn(LPGUID, PERFLIBREQUEST, PHANDLE) -> ULONG;
pub type FnPerfStartProviderEx =
    unsafe extern "system" fn(LPGUID, PPERF_PROVIDER_CONTEXT, PHANDLE) -> ULONG;
pub type FnPerfStopProvider = unsafe extern "system" fn(HANDLE) -> ULONG;
pub type FnPostQueuedCompletionStatus =
    unsafe extern "system" fn(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED) -> BOOL;
pub type FnPrefetchVirtualMemory =
    unsafe extern "system" fn(HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG) -> BOOL;
pub type FnPrivilegeCheck = unsafe extern "system" fn(HANDLE, PPRIVILEGE_SET, LPBOOL) -> BOOL;
pub type FnPrivilegedServiceAuditAlarmW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, HANDLE, PPRIVILEGE_SET, BOOL) -> BOOL;
pub type FnProcessIdToSessionId = unsafe extern "system" fn(DWORD, *mut DWORD) -> BOOL;
pub type FnPssCaptureSnapshot =
    unsafe extern "system" fn(HANDLE, PSS_CAPTURE_FLAGS, DWORD, *mut HPSS) -> DWORD;
pub type FnPssDuplicateSnapshot =
    unsafe extern "system" fn(HANDLE, HPSS, HANDLE, *mut HPSS, PSS_DUPLICATE_FLAGS) -> DWORD;
pub type FnPssFreeSnapshot = unsafe extern "system" fn(HANDLE, HPSS) -> DWORD;
pub type FnPssQuerySnapshot =
    unsafe extern "system" fn(HPSS, PSS_QUERY_INFORMATION_CLASS, *mut c_void, DWORD) -> DWORD;
pub type FnPssWalkMarkerCreate =
    unsafe extern "system" fn(*const PSS_ALLOCATOR, *mut HPSSWALK) -> DWORD;
pub type FnPssWalkMarkerFree = unsafe extern "system" fn(HPSSWALK) -> DWORD;
pub type FnPssWalkMarkerGetPosition = unsafe extern "system" fn(HPSSWALK, *mut ULONG_PTR) -> DWORD;
pub type FnPssWalkMarkerSeekToBeginning = unsafe extern "system" fn(HPSS) -> DWORD;
pub type FnPssWalkMarkerSetPosition = unsafe extern "system" fn(HPSSWALK, ULONG_PTR) -> DWORD;
pub type FnPssWalkSnapshot = unsafe extern "system" fn(
    HPSS,
    PSS_WALK_INFORMATION_CLASS,
    HPSSWALK,
    *mut c_void,
    DWORD,
) -> DWORD;
pub type FnPulseEvent = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnPurgeComm = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnQueryActCtxSettingsW =
    unsafe extern "system" fn(DWORD, HANDLE, PCWSTR, PCWSTR, PWSTR, SIZE_T, *mut SIZE_T) -> BOOL;
pub type FnQueryActCtxW =
    unsafe extern "system" fn(DWORD, HANDLE, PVOID, ULONG, PVOID, SIZE_T, *mut SIZE_T) -> BOOL;
pub type FnQueryDepthSList = unsafe extern "system" fn(PSLIST_HEADER) -> USHORT;
pub type FnQueryDosDeviceW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnQueryFullProcessImageNameA =
    unsafe extern "system" fn(HANDLE, DWORD, LPSTR, PDWORD) -> BOOL;
pub type FnQueryFullProcessImageNameW =
    unsafe extern "system" fn(HANDLE, DWORD, LPWSTR, PDWORD) -> BOOL;
pub type FnQueryIdleProcessorCycleTime = unsafe extern "system" fn(PULONG, PULONG64) -> BOOL;
pub type FnQueryIdleProcessorCycleTimeEx =
    unsafe extern "system" fn(USHORT, PULONG, PULONG64) -> BOOL;
pub type FnQueryMemoryResourceNotification = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnQueryPerformanceCounter = unsafe extern "system" fn(*mut LARGE_INTEGER) -> BOOL;
pub type FnQueryPerformanceFrequency = unsafe extern "system" fn(*mut LARGE_INTEGER) -> BOOL;
pub type FnQueryProcessAffinityUpdateMode = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnQueryProcessCycleTime = unsafe extern "system" fn(HANDLE, PULONG64) -> BOOL;
pub type FnQueryProtectedPolicy = unsafe extern "system" fn(LPCGUID, PULONG_PTR) -> BOOL;
pub type FnQuerySecurityAccessMask = unsafe extern "system" fn(SECURITY_INFORMATION, LPDWORD) -> ();
pub type FnQueryThreadCycleTime = unsafe extern "system" fn(HANDLE, PULONG64) -> BOOL;
pub type FnQueryThreadpoolStackInformation =
    unsafe extern "system" fn(PTP_POOL, PTP_POOL_STACK_INFORMATION) -> BOOL;
pub type FnQueryUnbiasedInterruptTime = unsafe extern "system" fn(PULONGLONG) -> BOOL;
pub type FnQueryWorkingSet = unsafe extern "system" fn(HANDLE, PVOID, DWORD) -> BOOL;
pub type FnQueryWorkingSetEx = unsafe extern "system" fn(HANDLE, PVOID, DWORD) -> BOOL;
pub type FnQueueUserAPC = unsafe extern "system" fn(PAPCFUNC, HANDLE, ULONG_PTR) -> DWORD;
pub type FnQueueUserWorkItem =
    unsafe extern "system" fn(LPTHREAD_START_ROUTINE, PVOID, ULONG) -> BOOL;
pub type FnRaiseException = unsafe extern "system" fn(DWORD, DWORD, DWORD, *const ULONG_PTR) -> ();
pub type FnRaiseFailFastException =
    unsafe extern "system" fn(PEXCEPTION_RECORD, PCONTEXT, DWORD) -> ();
pub type FnReOpenFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD) -> HANDLE;
pub type FnReadConsoleA =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPDWORD, PCONSOLE_READCONSOLE_CONTROL) -> BOOL;
pub type FnReadConsoleInputA =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnReadConsoleInputW =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnReadConsoleOutputA =
    unsafe extern "system" fn(HANDLE, PCHAR_INFO, COORD, COORD, PSMALL_RECT) -> BOOL;
pub type FnReadConsoleOutputAttribute =
    unsafe extern "system" fn(HANDLE, LPWORD, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnReadConsoleOutputCharacterA =
    unsafe extern "system" fn(HANDLE, LPSTR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnReadConsoleOutputCharacterW =
    unsafe extern "system" fn(HANDLE, LPWSTR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnReadConsoleOutputW =
    unsafe extern "system" fn(HANDLE, PCHAR_INFO, COORD, COORD, PSMALL_RECT) -> BOOL;
pub type FnReadConsoleW =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPDWORD, PCONSOLE_READCONSOLE_CONTROL) -> BOOL;
pub type FnReadDirectoryChangesW = unsafe extern "system" fn(
    HANDLE,
    LPVOID,
    DWORD,
    BOOL,
    DWORD,
    LPDWORD,
    LPOVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL;
pub type FnReadFile =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) -> BOOL;
pub type FnReadFileEx = unsafe extern "system" fn(
    HANDLE,
    LPVOID,
    DWORD,
    LPOVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL;
pub type FnReadFileScatter = unsafe extern "system" fn(
    HANDLE,
    *mut FILE_SEGMENT_ELEMENT,
    DWORD,
    LPDWORD,
    LPOVERLAPPED,
) -> BOOL;
pub type FnReadProcessMemory =
    unsafe extern "system" fn(HANDLE, LPCVOID, LPVOID, SIZE_T, *mut SIZE_T) -> BOOL;
pub type FnReclaimVirtualMemory = unsafe extern "system" fn(*const c_void, SIZE_T) -> DWORD;
pub type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> LSTATUS;
pub type FnRegCopyTreeW = unsafe extern "system" fn(HKEY, LPCWSTR, HKEY) -> LSTATUS;
pub type FnRegCreateKeyExA = unsafe extern "system" fn(
    HKEY,
    LPCSTR,
    DWORD,
    LPSTR,
    DWORD,
    REGSAM,
    LPSECURITY_ATTRIBUTES,
    PHKEY,
    LPDWORD,
) -> LSTATUS;
pub type FnRegCreateKeyExW = unsafe extern "system" fn(
    HKEY,
    LPCWSTR,
    DWORD,
    LPWSTR,
    DWORD,
    REGSAM,
    LPSECURITY_ATTRIBUTES,
    PHKEY,
    LPDWORD,
) -> LSTATUS;
pub type FnRegDeleteKeyExA = unsafe extern "system" fn(HKEY, LPCSTR, REGSAM, DWORD) -> LSTATUS;
pub type FnRegDeleteKeyExW = unsafe extern "system" fn(HKEY, LPCWSTR, REGSAM, DWORD) -> LSTATUS;
pub type FnRegDeleteKeyValueA = unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR) -> LSTATUS;
pub type FnRegDeleteKeyValueW = unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR) -> LSTATUS;
pub type FnRegDeleteTreeA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegDeleteTreeW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegDeleteValueA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegDisablePredefinedCacheEx = unsafe extern "system" fn() -> LSTATUS;
pub type FnRegEnumKeyExA = unsafe extern "system" fn(
    HKEY,
    DWORD,
    LPSTR,
    LPDWORD,
    LPDWORD,
    LPSTR,
    LPDWORD,
    PFILETIME,
) -> LSTATUS;
pub type FnRegEnumKeyExW = unsafe extern "system" fn(
    HKEY,
    DWORD,
    LPWSTR,
    LPDWORD,
    LPDWORD,
    LPWSTR,
    LPDWORD,
    PFILETIME,
) -> LSTATUS;
pub type FnRegEnumValueA = unsafe extern "system" fn(
    HKEY,
    DWORD,
    LPSTR,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPBYTE,
    LPDWORD,
) -> LSTATUS;
pub type FnRegEnumValueW = unsafe extern "system" fn(
    HKEY,
    DWORD,
    LPWSTR,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPBYTE,
    LPDWORD,
) -> LSTATUS;
pub type FnRegFlushKey = unsafe extern "system" fn(HKEY) -> LSTATUS;
pub type FnRegGetKeySecurity =
    unsafe extern "system" fn(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD) -> LSTATUS;
pub type FnRegGetValueA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD) -> LSTATUS;
pub type FnRegGetValueW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD) -> LSTATUS;
pub type FnRegLoadAppKeyA =
    unsafe extern "system" fn(LPCSTR, PHKEY, REGSAM, DWORD, DWORD) -> LSTATUS;
pub type FnRegLoadAppKeyW =
    unsafe extern "system" fn(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD) -> LSTATUS;
pub type FnRegLoadKeyA = unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR) -> LSTATUS;
pub type FnRegLoadKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR) -> LSTATUS;
pub type FnRegLoadMUIStringA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPSTR, DWORD, LPDWORD, DWORD, LPCSTR) -> LSTATUS;
pub type FnRegLoadMUIStringW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPWSTR, DWORD, LPDWORD, DWORD, LPCWSTR) -> LSTATUS;
pub type FnRegNotifyChangeKeyValue =
    unsafe extern "system" fn(HKEY, BOOL, DWORD, HANDLE, BOOL) -> LSTATUS;
pub type FnRegOpenCurrentUser = unsafe extern "system" fn(REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOpenKeyExA = unsafe extern "system" fn(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOpenKeyExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOpenUserClassesRoot =
    unsafe extern "system" fn(HANDLE, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegQueryInfoKeyA = unsafe extern "system" fn(
    HKEY,
    LPSTR,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    PFILETIME,
) -> LSTATUS;
pub type FnRegQueryInfoKeyW = unsafe extern "system" fn(
    HKEY,
    LPWSTR,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    PFILETIME,
) -> LSTATUS;
pub type FnRegQueryMultipleValuesA =
    unsafe extern "system" fn(HKEY, PVALENTA, DWORD, LPSTR, LPDWORD) -> LSTATUS;
pub type FnRegQueryMultipleValuesW =
    unsafe extern "system" fn(HKEY, PVALENTW, DWORD, LPWSTR, LPDWORD) -> LSTATUS;
pub type FnRegQueryValueExA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) -> LSTATUS;
pub type FnRegQueryValueExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) -> LSTATUS;
pub type FnRegRestoreKeyA = unsafe extern "system" fn(HKEY, LPCSTR, DWORD) -> LSTATUS;
pub type FnRegRestoreKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, DWORD) -> LSTATUS;
pub type FnRegSaveKeyExA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES, DWORD) -> LSTATUS;
pub type FnRegSaveKeyExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES, DWORD) -> LSTATUS;
pub type FnRegSetKeySecurity =
    unsafe extern "system" fn(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> LSTATUS;
pub type FnRegSetKeyValueA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD) -> LSTATUS;
pub type FnRegSetKeyValueW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD) -> LSTATUS;
pub type FnRegSetValueExA =
    unsafe extern "system" fn(HKEY, LPCSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegSetValueExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegUnLoadKeyA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegUnLoadKeyW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegisterApplicationRestart = unsafe extern "system" fn(PCWSTR, DWORD) -> HRESULT;
pub type FnRegisterBadMemoryNotification =
    unsafe extern "system" fn(PBAD_MEMORY_CALLBACK_ROUTINE) -> PVOID;
pub type FnRegisterTraceGuidsW = unsafe extern "system" fn(
    WMIDPREQUEST,
    PVOID,
    LPCGUID,
    ULONG,
    PTRACE_GUID_REGISTRATION,
    LPCWSTR,
    LPCWSTR,
    PTRACEHANDLE,
) -> ULONG;
pub type FnReleaseActCtx = unsafe extern "system" fn(HANDLE) -> ();
pub type FnReleaseMutex = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnReleaseMutexWhenCallbackReturns =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE) -> ();
pub type FnReleaseSRWLockExclusive = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnReleaseSRWLockShared = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnReleaseSemaphore = unsafe extern "system" fn(HANDLE, LONG, LPLONG) -> BOOL;
pub type FnReleaseSemaphoreWhenCallbackReturns =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE, DWORD) -> ();
pub type FnRemoveDirectoryA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnRemoveDirectoryW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnRemoveDllDirectory = unsafe extern "system" fn(DLL_DIRECTORY_COOKIE) -> BOOL;
pub type FnRemoveVectoredContinueHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnRemoveVectoredExceptionHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnReplaceFileW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID) -> ();
pub type FnResetEvent = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnResetWriteWatch = unsafe extern "system" fn(LPVOID, SIZE_T) -> UINT;
pub type FnResizePseudoConsole = unsafe extern "system" fn(HPCON, COORD) -> HRESULT;
pub type FnResolveLocaleName = unsafe extern "system" fn(LPCWSTR, LPWSTR, c_int) -> c_int;
pub type FnRestoreLastError = unsafe extern "system" fn(DWORD) -> ();
pub type FnResumeThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnRevertToSelf = unsafe extern "system" fn() -> BOOL;
pub type FnScrollConsoleScreenBufferA = unsafe extern "system" fn(
    HANDLE,
    *const SMALL_RECT,
    *const SMALL_RECT,
    COORD,
    *const CHAR_INFO,
) -> BOOL;
pub type FnScrollConsoleScreenBufferW = unsafe extern "system" fn(
    HANDLE,
    *const SMALL_RECT,
    *const SMALL_RECT,
    COORD,
    *const CHAR_INFO,
) -> BOOL;
pub type FnSearchPathA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, DWORD, LPSTR, *mut LPSTR) -> DWORD;
pub type FnSearchPathW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPWSTR, *mut LPWSTR) -> DWORD;
pub type FnSetAclInformation =
    unsafe extern "system" fn(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS) -> BOOL;
pub type FnSetCachedSigningLevel = unsafe extern "system" fn(PHANDLE, ULONG, ULONG, HANDLE) -> BOOL;
pub type FnSetCalendarInfoW = unsafe extern "system" fn(LCID, CALID, CALTYPE, LPCWSTR) -> BOOL;
pub type FnSetCommBreak = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnSetCommConfig = unsafe extern "system" fn(HANDLE, LPCOMMCONFIG, DWORD) -> BOOL;
pub type FnSetCommMask = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetCommState = unsafe extern "system" fn(HANDLE, LPDCB) -> BOOL;
pub type FnSetCommTimeouts = unsafe extern "system" fn(HANDLE, LPCOMMTIMEOUTS) -> BOOL;
pub type FnSetComputerNameA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnSetComputerNameEx2W =
    unsafe extern "system" fn(COMPUTER_NAME_FORMAT, DWORD, LPCWSTR) -> BOOL;
pub type FnSetComputerNameExA = unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPCSTR) -> BOOL;
pub type FnSetComputerNameExW = unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPCWSTR) -> BOOL;
pub type FnSetComputerNameW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnSetConsoleActiveScreenBuffer = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnSetConsoleCP = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnSetConsoleCtrlHandler = unsafe extern "system" fn(PHANDLER_ROUTINE, BOOL) -> BOOL;
pub type FnSetConsoleCursorInfo =
    unsafe extern "system" fn(HANDLE, *const CONSOLE_CURSOR_INFO) -> BOOL;
pub type FnSetConsoleCursorPosition = unsafe extern "system" fn(HANDLE, COORD) -> BOOL;
pub type FnSetConsoleDisplayMode = unsafe extern "system" fn(HANDLE, DWORD, PCOORD) -> BOOL;
pub type FnSetConsoleHistoryInfo = unsafe extern "system" fn(PCONSOLE_HISTORY_INFO) -> BOOL;
pub type FnSetConsoleMode = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetConsoleOutputCP = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnSetConsoleScreenBufferInfoEx =
    unsafe extern "system" fn(HANDLE, PCONSOLE_SCREEN_BUFFER_INFOEX) -> BOOL;
pub type FnSetConsoleScreenBufferSize = unsafe extern "system" fn(HANDLE, COORD) -> BOOL;
pub type FnSetConsoleTextAttribute = unsafe extern "system" fn(HANDLE, WORD) -> BOOL;
pub type FnSetConsoleTitleA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnSetConsoleTitleW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnSetConsoleWindowInfo =
    unsafe extern "system" fn(HANDLE, BOOL, *const SMALL_RECT) -> BOOL;
pub type FnSetCriticalSectionSpinCount =
    unsafe extern "system" fn(LPCRITICAL_SECTION, DWORD) -> DWORD;
pub type FnSetCurrentConsoleFontEx =
    unsafe extern "system" fn(HANDLE, BOOL, PCONSOLE_FONT_INFOEX) -> BOOL;
pub type FnSetCurrentDirectoryA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnSetCurrentDirectoryW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnSetDefaultDllDirectories = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnSetDynamicTimeZoneInformation =
    unsafe extern "system" fn(*const DYNAMIC_TIME_ZONE_INFORMATION) -> BOOL;
pub type FnSetEndOfFile = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnSetEnvironmentStringsW = unsafe extern "system" fn(LPWCH) -> BOOL;
pub type FnSetEnvironmentVariableA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> BOOL;
pub type FnSetEnvironmentVariableW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> BOOL;
pub type FnSetErrorMode = unsafe extern "system" fn(UINT) -> UINT;
pub type FnSetEvent = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnSetEventWhenCallbackReturns =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE) -> ();
pub type FnSetFileApisToANSI = unsafe extern "system" fn() -> ();
pub type FnSetFileApisToOEM = unsafe extern "system" fn() -> ();
pub type FnSetFileAttributesA = unsafe extern "system" fn(LPCSTR, DWORD) -> BOOL;
pub type FnSetFileAttributesW = unsafe extern "system" fn(LPCWSTR, DWORD) -> BOOL;
pub type FnSetFileInformationByHandle =
    unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetFileIoOverlappedRange = unsafe extern "system" fn(HANDLE, PUCHAR, ULONG) -> BOOL;
pub type FnSetFilePointer = unsafe extern "system" fn(HANDLE, LONG, PLONG, DWORD) -> DWORD;
pub type FnSetFilePointerEx =
    unsafe extern "system" fn(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) -> BOOL;
pub type FnSetFileSecurityW =
    unsafe extern "system" fn(LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetFileTime =
    unsafe extern "system" fn(HANDLE, *const FILETIME, *const FILETIME, *const FILETIME) -> BOOL;
pub type FnSetFileValidData = unsafe extern "system" fn(HANDLE, LONGLONG) -> BOOL;
pub type FnSetHandleCount = unsafe extern "system" fn(UINT) -> UINT;
pub type FnSetHandleInformation = unsafe extern "system" fn(HANDLE, DWORD, DWORD) -> BOOL;
pub type FnSetKernelObjectSecurity =
    unsafe extern "system" fn(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetLastError = unsafe extern "system" fn(DWORD) -> ();
pub type FnSetLocalTime = unsafe extern "system" fn(*const SYSTEMTIME) -> BOOL;
pub type FnSetLocaleInfoW = unsafe extern "system" fn(LCID, LCTYPE, LPCWSTR) -> BOOL;
pub type FnSetNamedPipeHandleState =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnSetPriorityClass = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetPrivateObjectSecurity = unsafe extern "system" fn(
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    PGENERIC_MAPPING,
    HANDLE,
) -> BOOL;
pub type FnSetPrivateObjectSecurityEx = unsafe extern "system" fn(
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    ULONG,
    PGENERIC_MAPPING,
    HANDLE,
) -> BOOL;
pub type FnSetProcessAffinityUpdateMode = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetProcessInformation =
    unsafe extern "system" fn(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetProcessMitigationPolicy =
    unsafe extern "system" fn(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T) -> BOOL;
pub type FnSetProcessPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PCZZWSTR, PULONG) -> BOOL;
pub type FnSetProcessPriorityBoost = unsafe extern "system" fn(HANDLE, BOOL) -> BOOL;
pub type FnSetProcessShutdownParameters = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnSetProcessWorkingSetSize = unsafe extern "system" fn(HANDLE, SIZE_T, SIZE_T) -> BOOL;
pub type FnSetProcessWorkingSetSizeEx =
    unsafe extern "system" fn(HANDLE, SIZE_T, SIZE_T, DWORD) -> BOOL;
pub type FnSetProtectedPolicy = unsafe extern "system" fn(LPCGUID, ULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnSetSecurityAccessMask = unsafe extern "system" fn(SECURITY_INFORMATION, LPDWORD) -> ();
pub type FnSetSecurityDescriptorControl = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL,
    SECURITY_DESCRIPTOR_CONTROL,
) -> BOOL;
pub type FnSetSecurityDescriptorDacl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL) -> BOOL;
pub type FnSetSecurityDescriptorGroup =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSID, BOOL) -> BOOL;
pub type FnSetSecurityDescriptorOwner =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSID, BOOL) -> BOOL;
pub type FnSetSecurityDescriptorRMControl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PUCHAR) -> DWORD;
pub type FnSetSecurityDescriptorSacl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL) -> BOOL;
pub type FnSetStdHandle = unsafe extern "system" fn(DWORD, HANDLE) -> BOOL;
pub type FnSetStdHandleEx = unsafe extern "system" fn(DWORD, HANDLE, PHANDLE) -> BOOL;
pub type FnSetSystemFileCacheSize = unsafe extern "system" fn(SIZE_T, SIZE_T, DWORD) -> BOOL;
pub type FnSetSystemTime = unsafe extern "system" fn(*const SYSTEMTIME) -> BOOL;
pub type FnSetSystemTimeAdjustment = unsafe extern "system" fn(DWORD, BOOL) -> BOOL;
pub type FnSetThreadContext = unsafe extern "system" fn(HANDLE, *const CONTEXT) -> BOOL;
pub type FnSetThreadErrorMode = unsafe extern "system" fn(DWORD, LPDWORD) -> BOOL;
pub type FnSetThreadGroupAffinity =
    unsafe extern "system" fn(HANDLE, *const GROUP_AFFINITY, PGROUP_AFFINITY) -> BOOL;
pub type FnSetThreadIdealProcessor = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;
pub type FnSetThreadIdealProcessorEx =
    unsafe extern "system" fn(HANDLE, PPROCESSOR_NUMBER, PPROCESSOR_NUMBER) -> BOOL;
pub type FnSetThreadInformation =
    unsafe extern "system" fn(HANDLE, THREAD_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetThreadLocale = unsafe extern "system" fn(LCID) -> BOOL;
pub type FnSetThreadPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PCZZWSTR, PULONG) -> BOOL;
pub type FnSetThreadPriority = unsafe extern "system" fn(HANDLE, c_int) -> BOOL;
pub type FnSetThreadPriorityBoost = unsafe extern "system" fn(HANDLE, BOOL) -> BOOL;
pub type FnSetThreadStackGuarantee = unsafe extern "system" fn(PULONG) -> BOOL;
pub type FnSetThreadToken = unsafe extern "system" fn(PHANDLE, HANDLE) -> BOOL;
pub type FnSetThreadUILanguage = unsafe extern "system" fn(LANGID) -> LANGID;
pub type FnSetThreadpoolStackInformation =
    unsafe extern "system" fn(PTP_POOL, PTP_POOL_STACK_INFORMATION) -> BOOL;
pub type FnSetThreadpoolThreadMaximum = unsafe extern "system" fn(PTP_POOL, DWORD) -> ();
pub type FnSetThreadpoolThreadMinimum = unsafe extern "system" fn(PTP_POOL, DWORD) -> BOOL;
pub type FnSetThreadpoolTimer = unsafe extern "system" fn(PTP_TIMER, PFILETIME, DWORD, DWORD) -> ();
pub type FnSetThreadpoolTimerEx =
    unsafe extern "system" fn(PTP_TIMER, PFILETIME, DWORD, DWORD) -> BOOL;
pub type FnSetThreadpoolWait = unsafe extern "system" fn(PTP_WAIT, HANDLE, PFILETIME) -> ();
pub type FnSetThreadpoolWaitEx =
    unsafe extern "system" fn(PTP_WAIT, HANDLE, PFILETIME, PVOID) -> BOOL;
pub type FnSetTimeZoneInformation = unsafe extern "system" fn(*const TIME_ZONE_INFORMATION) -> BOOL;
pub type FnSetTokenInformation =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetUnhandledExceptionFilter =
    unsafe extern "system" fn(LPTOP_LEVEL_EXCEPTION_FILTER) -> LPTOP_LEVEL_EXCEPTION_FILTER;
pub type FnSetUserGeoID = unsafe extern "system" fn(GEOID) -> BOOL;
pub type FnSetWaitableTimer = unsafe extern "system" fn(
    HANDLE,
    *const LARGE_INTEGER,
    LONG,
    PTIMERAPCROUTINE,
    LPVOID,
    BOOL,
) -> BOOL;
pub type FnSetWaitableTimerEx = unsafe extern "system" fn(
    HANDLE,
    *const LARGE_INTEGER,
    LONG,
    PTIMERAPCROUTINE,
    LPVOID,
    PREASON_CONTEXT,
    ULONG,
) -> BOOL;
pub type FnSetupComm = unsafe extern "system" fn(HANDLE, DWORD, DWORD) -> BOOL;
pub type FnSignalObjectAndWait = unsafe extern "system" fn(HANDLE, HANDLE, DWORD, BOOL) -> DWORD;
pub type FnSizeofResource = unsafe extern "system" fn(HMODULE, HRSRC) -> DWORD;
pub type FnSleep = unsafe extern "system" fn(DWORD) -> ();
pub type FnSleepConditionVariableCS =
    unsafe extern "system" fn(PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD) -> BOOL;
pub type FnSleepConditionVariableSRW =
    unsafe extern "system" fn(PCONDITION_VARIABLE, PSRWLOCK, DWORD, ULONG) -> BOOL;
pub type FnSleepEx = unsafe extern "system" fn(DWORD, BOOL) -> DWORD;
pub type FnStartThreadpoolIo = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnSubmitThreadpoolWork = unsafe extern "system" fn(PTP_WORK) -> ();
pub type FnSuspendThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnSwitchToFiber = unsafe extern "system" fn(LPVOID) -> ();
pub type FnSwitchToThread = unsafe extern "system" fn() -> BOOL;
pub type FnSystemTimeToFileTime = unsafe extern "system" fn(*const SYSTEMTIME, LPFILETIME) -> BOOL;
pub type FnSystemTimeToTzSpecificLocalTime = unsafe extern "system" fn(
    *const TIME_ZONE_INFORMATION,
    *const SYSTEMTIME,
    LPSYSTEMTIME,
) -> BOOL;
pub type FnSystemTimeToTzSpecificLocalTimeEx = unsafe extern "system" fn(
    *const DYNAMIC_TIME_ZONE_INFORMATION,
    *const SYSTEMTIME,
    LPSYSTEMTIME,
) -> BOOL;
pub type FnTerminateEnclave = unsafe extern "system" fn(LPVOID, BOOL) -> BOOL;
pub type FnTerminateProcess = unsafe extern "system" fn(HANDLE, UINT) -> BOOL;
pub type FnTerminateThread = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnTlsAlloc = unsafe extern "system" fn() -> DWORD;
pub type FnTlsFree = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnTlsGetValue = unsafe extern "system" fn(DWORD) -> LPVOID;
pub type FnTlsSetValue = unsafe extern "system" fn(DWORD, LPVOID) -> BOOL;
pub type FnTraceEvent = unsafe extern "system" fn(TRACEHANDLE, PEVENT_TRACE_HEADER) -> ULONG;
pub type FnTraceMessage = unsafe extern "system" fn(TRACEHANDLE, ULONG, LPGUID, USHORT) -> ULONG;
pub type FnTraceMessageVa =
    unsafe extern "system" fn(TRACEHANDLE, ULONG, LPGUID, USHORT, va_list) -> ();
pub type FnTransactNamedPipe =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) -> BOOL;
pub type FnTransmitCommChar = unsafe extern "system" fn(HANDLE, c_char) -> BOOL;
pub type FnTryAcquireSRWLockExclusive = unsafe extern "system" fn(PSRWLOCK) -> BOOLEAN;
pub type FnTryAcquireSRWLockShared = unsafe extern "system" fn(PSRWLOCK) -> BOOLEAN;
pub type FnTryEnterCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> BOOL;
pub type FnTrySubmitThreadpoolCallback =
    unsafe extern "system" fn(PTP_SIMPLE_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> BOOL;
pub type FnTzSpecificLocalTimeToSystemTime = unsafe extern "system" fn(
    *const TIME_ZONE_INFORMATION,
    *const SYSTEMTIME,
    LPSYSTEMTIME,
) -> BOOL;
pub type FnTzSpecificLocalTimeToSystemTimeEx = unsafe extern "system" fn(
    *const DYNAMIC_TIME_ZONE_INFORMATION,
    *const SYSTEMTIME,
    LPSYSTEMTIME,
) -> BOOL;
pub type FnUnhandledExceptionFilter = unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG;
pub type FnUnlockFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD) -> BOOL;
pub type FnUnlockFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED) -> BOOL;
pub type FnUnmapViewOfFile = unsafe extern "system" fn(LPCVOID) -> BOOL;
pub type FnUnmapViewOfFile2 = unsafe extern "system" fn(HANDLE, PVOID, ULONG) -> BOOL;
pub type FnUnmapViewOfFileEx = unsafe extern "system" fn(PVOID, ULONG) -> BOOL;
pub type FnUnregisterApplicationRestart = unsafe extern "system" fn() -> HRESULT;
pub type FnUnregisterBadMemoryNotification = unsafe extern "system" fn(PVOID) -> BOOL;
pub type FnUnregisterTraceGuids = unsafe extern "system" fn(TRACEHANDLE) -> ULONG;
pub type FnUnregisterWaitEx = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnUpdateProcThreadAttribute = unsafe extern "system" fn(
    LPPROC_THREAD_ATTRIBUTE_LIST,
    DWORD,
    DWORD_PTR,
    PVOID,
    SIZE_T,
    PVOID,
    PSIZE_T,
) -> BOOL;
pub type FnVerLanguageNameA = unsafe extern "system" fn(DWORD, LPSTR, DWORD) -> DWORD;
pub type FnVerLanguageNameW = unsafe extern "system" fn(DWORD, LPWSTR, DWORD) -> DWORD;
pub type FnVerQueryValueA = unsafe extern "system" fn(LPCVOID, LPCSTR, PUINT) -> BOOL;
pub type FnVerQueryValueW = unsafe extern "system" fn(LPCVOID, LPCWSTR, PUINT) -> BOOL;
pub type FnVerSetConditionMask = unsafe extern "system" fn(ULONGLONG, DWORD, BYTE) -> ULONGLONG;
pub type FnVerifyScripts = unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPCWSTR, c_int) -> BOOL;
pub type FnVirtualAlloc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
pub type FnVirtualAllocEx =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
pub type FnVirtualAllocExNuma =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD) -> LPVOID;
pub type FnVirtualAllocFromApp = unsafe extern "system" fn(PVOID, SIZE_T, ULONG, ULONG) -> PVOID;
pub type FnVirtualFree = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD) -> BOOL;
pub type FnVirtualFreeEx = unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD) -> BOOL;
pub type FnVirtualLock = unsafe extern "system" fn(LPVOID, SIZE_T) -> BOOL;
pub type FnVirtualProtect = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, PDWORD) -> BOOL;
pub type FnVirtualProtectEx =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) -> BOOL;
pub type FnVirtualProtectFromApp = unsafe extern "system" fn(PVOID, SIZE_T, ULONG, PULONG) -> BOOL;
pub type FnVirtualQuery =
    unsafe extern "system" fn(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T;
pub type FnVirtualQueryEx =
    unsafe extern "system" fn(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T;
pub type FnVirtualUnlock = unsafe extern "system" fn(LPVOID, SIZE_T) -> BOOL;
pub type FnWaitCommEvent = unsafe extern "system" fn(HANDLE, LPDWORD, LPOVERLAPPED) -> BOOL;
pub type FnWaitForDebugEvent = unsafe extern "system" fn(LPDEBUG_EVENT, DWORD) -> BOOL;
pub type FnWaitForDebugEventEx = unsafe extern "system" fn(LPDEBUG_EVENT, DWORD) -> BOOL;
pub type FnWaitForMultipleObjects =
    unsafe extern "system" fn(DWORD, *const HANDLE, BOOL, DWORD) -> DWORD;
pub type FnWaitForMultipleObjectsEx =
    unsafe extern "system" fn(DWORD, *const HANDLE, BOOL, DWORD, BOOL) -> DWORD;
pub type FnWaitForSingleObject = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;
pub type FnWaitForSingleObjectEx = unsafe extern "system" fn(HANDLE, DWORD, BOOL) -> DWORD;
pub type FnWaitForThreadpoolIoCallbacks = unsafe extern "system" fn(PTP_IO, BOOL) -> ();
pub type FnWaitForThreadpoolTimerCallbacks = unsafe extern "system" fn(PTP_TIMER, BOOL) -> ();
pub type FnWaitForThreadpoolWaitCallbacks = unsafe extern "system" fn(PTP_WAIT, BOOL) -> ();
pub type FnWaitForThreadpoolWorkCallbacks = unsafe extern "system" fn(PTP_WORK, BOOL) -> ();
pub type FnWaitNamedPipeW = unsafe extern "system" fn(LPCWSTR, DWORD) -> BOOL;
pub type FnWaitOnAddress = unsafe extern "system" fn(*mut VOID, PVOID, SIZE_T, DWORD) -> BOOL;
pub type FnWakeAllConditionVariable = unsafe extern "system" fn(PCONDITION_VARIABLE) -> ();
pub type FnWakeByAddressAll = unsafe extern "system" fn(PVOID) -> ();
pub type FnWakeByAddressSingle = unsafe extern "system" fn(PVOID) -> ();
pub type FnWakeConditionVariable = unsafe extern "system" fn(PCONDITION_VARIABLE) -> ();
pub type FnWerGetFlags = unsafe extern "system" fn(HANDLE, PDWORD) -> HRESULT;
pub type FnWerRegisterFile =
    unsafe extern "system" fn(PCWSTR, WER_REGISTER_FILE_TYPE, DWORD) -> HRESULT;
pub type FnWerRegisterMemoryBlock = unsafe extern "system" fn(PVOID, DWORD) -> HRESULT;
pub type FnWerRegisterRuntimeExceptionModule = unsafe extern "system" fn(PCWSTR, PVOID) -> HRESULT;
pub type FnWerSetFlags = unsafe extern "system" fn(DWORD) -> HRESULT;
pub type FnWerUnregisterFile = unsafe extern "system" fn(PCWSTR) -> HRESULT;
pub type FnWerUnregisterMemoryBlock = unsafe extern "system" fn(PVOID) -> HRESULT;
pub type FnWerUnregisterRuntimeExceptionModule =
    unsafe extern "system" fn(PCWSTR, PVOID) -> HRESULT;
pub type FnWideCharToMultiByte =
    unsafe extern "system" fn(UINT, DWORD, LPCWSTR, c_int, LPSTR, c_int, LPCSTR, LPBOOL) -> c_int;
pub type FnWow64DisableWow64FsRedirection = unsafe extern "system" fn(*mut PVOID) -> BOOL;
pub type FnWow64EnableWow64FsRedirection = unsafe extern "system" fn(BOOLEAN) -> BOOLEAN;
pub type FnWow64GetThreadContext = unsafe extern "system" fn(HANDLE, PWOW64_CONTEXT) -> BOOL;
pub type FnWow64RevertWow64FsRedirection = unsafe extern "system" fn(PVOID) -> BOOL;
pub type FnWow64SetThreadContext = unsafe extern "system" fn(HANDLE, *const WOW64_CONTEXT) -> BOOL;
pub type FnWow64SuspendThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnWriteConsoleA =
    unsafe extern "system" fn(HANDLE, *const VOID, DWORD, LPDWORD, LPVOID) -> BOOL;
pub type FnWriteConsoleInputA =
    unsafe extern "system" fn(HANDLE, *const INPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnWriteConsoleInputW =
    unsafe extern "system" fn(HANDLE, *const INPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnWriteConsoleOutputA =
    unsafe extern "system" fn(HANDLE, *const CHAR_INFO, COORD, COORD, PSMALL_RECT) -> BOOL;
pub type FnWriteConsoleOutputAttribute =
    unsafe extern "system" fn(HANDLE, *const WORD, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnWriteConsoleOutputCharacterA =
    unsafe extern "system" fn(HANDLE, LPCSTR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnWriteConsoleOutputCharacterW =
    unsafe extern "system" fn(HANDLE, LPCWSTR, DWORD, COORD, LPDWORD) -> BOOL;
pub type FnWriteConsoleOutputW =
    unsafe extern "system" fn(HANDLE, *const CHAR_INFO, COORD, COORD, PSMALL_RECT) -> BOOL;
pub type FnWriteConsoleW =
    unsafe extern "system" fn(HANDLE, *const VOID, DWORD, LPDWORD, LPVOID) -> BOOL;
pub type FnWriteFile =
    unsafe extern "system" fn(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) -> BOOL;
pub type FnWriteFileEx = unsafe extern "system" fn(
    HANDLE,
    LPCVOID,
    DWORD,
    LPOVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL;
pub type FnWriteFileGather = unsafe extern "system" fn(
    HANDLE,
    *mut FILE_SEGMENT_ELEMENT,
    DWORD,
    LPDWORD,
    LPOVERLAPPED,
) -> BOOL;
pub type FnWriteProcessMemory =
    unsafe extern "system" fn(HANDLE, LPVOID, LPCVOID, SIZE_T, *mut SIZE_T) -> BOOL;
pub type FnZombifyActCtx = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnlstrcmpA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> c_int;
pub type FnlstrcmpW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> c_int;
pub type FnlstrcmpiA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> c_int;
pub type FnlstrcmpiW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> c_int;
pub type FnlstrcpynA = unsafe extern "system" fn(LPSTR, LPCSTR, c_int) -> LPSTR;
pub type FnlstrcpynW = unsafe extern "system" fn(LPWSTR, LPCWSTR, c_int) -> LPWSTR;
pub type FnlstrlenA = unsafe extern "system" fn(LPCSTR) -> c_int;
pub type FnlstrlenW = unsafe extern "system" fn(LPCWSTR) -> c_int;
