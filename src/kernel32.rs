use crate::types::{CONTEXT, LPCONTEXT, PCONTEXT};
use winapi::ctypes::{c_char, c_int, c_long, c_void};
use winapi::shared::basetsd::{
    DWORD64, DWORD_PTR, LONG_PTR, PDWORD64, PDWORD_PTR, PSIZE_T, PULONG64, PULONG_PTR, SIZE_T,
    UINT_PTR, ULONG64, ULONG_PTR,
};
use winapi::shared::guiddef::{GUID, LPCGUID};
use winapi::shared::minwindef::{
    ATOM, BOOL, BYTE, DWORD, FARPROC, FILETIME, HFILE, HGLOBAL, HKEY, HLOCAL, HMODULE, HRSRC, INT,
    LPARAM, LPBOOL, LPBYTE, LPCVOID, LPDWORD, LPFILETIME, LPHANDLE, LPINT, LPLONG, LPVOID, LPWORD,
    PBOOL, PDWORD, PFILETIME, PHKEY, PUCHAR, PULONG, PUSHORT, UCHAR, UINT, ULONG, USHORT, WORD,
};
use winapi::shared::ntdef::{
    BOOLEAN, CHAR, DWORDLONG, GROUP_AFFINITY, HANDLE, HRESULT, LANGID, LARGE_INTEGER, LCID, LONG,
    LONGLONG, LPCCH, LPCH, LPCSTR, LPCUWSTR, LPCWCH, LPCWSTR, LPSTR, LPWCH, LPWSTR, PBOOLEAN,
    PCNZCH, PCNZWCH, PCUWSTR, PCWSTR, PCZZWSTR, PGROUP_AFFINITY, PHANDLE, PLARGE_INTEGER, PLONG,
    PPROCESSOR_NUMBER, PULARGE_INTEGER, PULONGLONG, PUWSTR, PVOID, PWSTR, PZZWSTR, ULONGLONG, VOID,
    WCHAR,
};
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::LPTOP_LEVEL_EXCEPTION_FILTER;
use winapi::um::fileapi::{
    LPBY_HANDLE_FILE_INFORMATION, LPCREATEFILE2_EXTENDED_PARAMETERS, STREAM_INFO_LEVELS,
};
use winapi::um::heapapi::LPHEAP_SUMMARY;
use winapi::um::jobapi2::JOBOBJECT_IO_RATE_CONTROL_INFORMATION;
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
    LPCRITICAL_SECTION, LPDEBUG_EVENT, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE,
    LPOVERLAPPED_ENTRY, LPPROCESS_HEAP_ENTRY, LPSECURITY_ATTRIBUTES, LPSYSTEMTIME,
    LPTHREAD_START_ROUTINE, LPWIN32_FIND_DATAA, LPWIN32_FIND_DATAW, PCRITICAL_SECTION,
    PREASON_CONTEXT, PSECURITY_ATTRIBUTES, SECURITY_ATTRIBUTES, SYSTEMTIME,
};
use winapi::um::mmsystem::{LPTIMECAPS, MMRESULT};
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
use winapi::um::tlhelp32::{
    LPHEAPENTRY32, LPHEAPLIST32, LPMODULEENTRY32, LPMODULEENTRY32W, LPPROCESSENTRY32,
    LPPROCESSENTRY32W, LPTHREADENTRY32,
};
use winapi::um::werapi::WER_REGISTER_FILE_TYPE;
use winapi::um::winbase::{
    APPLICATION_RECOVERY_CALLBACK, COPYFILE2_EXTENDED_PARAMETERS, DEP_SYSTEM_POLICY_TYPE,
    LPCOMMCONFIG, LPCOMMPROP, LPCOMMTIMEOUTS, LPCOMSTAT, LPDCB, LPFIBER_START_ROUTINE,
    LPFILE_ID_DESCRIPTOR, LPLDT_ENTRY, LPMEMORYSTATUS, LPOFSTRUCT, LPPROGRESS_ROUTINE,
    LPSYSTEM_POWER_STATUS, PACTCTX_SECTION_KEYED_DATA, PCACTCTXA, PCACTCTXW, PUMS_COMPLETION_LIST,
    PUMS_CONTEXT, PUMS_SCHEDULER_STARTUP_INFO, PUMS_SYSTEM_THREAD_INFORMATION,
    UMS_THREAD_INFO_CLASS,
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
    CALID, CALINFO_ENUMPROCA, CALINFO_ENUMPROCEXA, CALINFO_ENUMPROCEXEX, CALINFO_ENUMPROCEXW,
    CALINFO_ENUMPROCW, CALTYPE, CODEPAGE_ENUMPROCA, CODEPAGE_ENUMPROCW, CURRENCYFMTA, CURRENCYFMTW,
    DATEFMT_ENUMPROCA, DATEFMT_ENUMPROCEXA, DATEFMT_ENUMPROCEXEX, DATEFMT_ENUMPROCEXW,
    DATEFMT_ENUMPROCW, GEOCLASS, GEOID, GEOTYPE, GEO_ENUMPROC, LANGGROUPLOCALE_ENUMPROCA,
    LANGGROUPLOCALE_ENUMPROCW, LANGUAGEGROUP_ENUMPROCA, LANGUAGEGROUP_ENUMPROCW, LCTYPE, LGRPID,
    LOCALE_ENUMPROCA, LOCALE_ENUMPROCEX, LOCALE_ENUMPROCW, LPCPINFO, LPCPINFOEXA, LPCPINFOEXW,
    LPNLSVERSIONINFO, LPNLSVERSIONINFOEX, NLS_FUNCTION, NORM_FORM, NUMBERFMTA, NUMBERFMTW,
    PFILEMUIINFO, TIMEFMT_ENUMPROCA, TIMEFMT_ENUMPROCEX, TIMEFMT_ENUMPROCW, UILANGUAGE_ENUMPROCA,
    UILANGUAGE_ENUMPROCW,
};
use winapi::um::winnt::{
    EXCEPTION_POINTERS, EXCEPTION_RECORD, EXECUTION_STATE, FILE_SEGMENT_ELEMENT,
    HEAP_INFORMATION_CLASS, JOBOBJECTINFOCLASS, LATENCY_TIME, LOGICAL_PROCESSOR_RELATIONSHIP,
    LPOSVERSIONINFOA, LPOSVERSIONINFOEXA, LPOSVERSIONINFOEXW, LPOSVERSIONINFOW, PACL, PAPCFUNC,
    PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PEXCEPTION_RECORD, PEXCEPTION_ROUTINE, PFIRMWARE_TYPE,
    PFLS_CALLBACK_FUNCTION, PGET_RUNTIME_FUNCTION_CALLBACK, PIO_COUNTERS, PJOB_SET_ARRAY,
    PKNONVOLATILE_CONTEXT_POINTERS, PMEMORY_BASIC_INFORMATION, POWER_REQUEST_TYPE,
    PPERFORMANCE_DATA, PROCESS_MITIGATION_POLICY, PRUNTIME_FUNCTION, PSECURE_MEMORY_CACHE_CALLBACK,
    PSECURITY_DESCRIPTOR, PSID, PSLIST_ENTRY, PSLIST_HEADER, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION, PTP_CALLBACK_ENVIRON, PTP_CALLBACK_INSTANCE,
    PTP_CLEANUP_GROUP, PTP_IO, PTP_POOL, PTP_POOL_STACK_INFORMATION, PTP_SIMPLE_CALLBACK,
    PTP_TIMER, PTP_TIMER_CALLBACK, PTP_WAIT, PTP_WAIT_CALLBACK, PTP_WORK, PTP_WORK_CALLBACK,
    PUNWIND_HISTORY_TABLE, PVECTORED_EXCEPTION_HANDLER, PWOW64_CONTEXT, PWOW64_LDT_ENTRY,
    SECURITY_INFORMATION, WAITORTIMERCALLBACK, WOW64_CONTEXT,
};
use winapi::um::winreg::{LSTATUS, REGSAM};
use winapi::vc::vadefs::va_list;
use winapi::vc::vcruntime::size_t;

pub type FnAcquireSRWLockExclusive = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnAcquireSRWLockShared = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnActivateActCtx = unsafe extern "system" fn(HANDLE, *mut ULONG_PTR) -> BOOL;
pub type FnAddAtomA = unsafe extern "system" fn(LPCSTR) -> ATOM;
pub type FnAddAtomW = unsafe extern "system" fn(LPCWSTR) -> ATOM;
pub type FnAddConsoleAliasA = unsafe extern "system" fn(LPSTR, LPSTR, LPSTR) -> BOOL;
pub type FnAddConsoleAliasW = unsafe extern "system" fn(LPWSTR, LPWSTR, LPWSTR) -> BOOL;
pub type FnAddDllDirectory = unsafe extern "system" fn(PCWSTR) -> DLL_DIRECTORY_COOKIE;
pub type FnAddIntegrityLabelToBoundaryDescriptor =
    unsafe extern "system" fn(*mut HANDLE, PSID) -> BOOL;
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
pub type FnAddSecureMemoryCacheCallback =
    unsafe extern "system" fn(PSECURE_MEMORY_CACHE_CALLBACK) -> BOOL;
pub type FnAddVectoredContinueHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnAddVectoredExceptionHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnAllocConsole = unsafe extern "system" fn() -> BOOL;
pub type FnAllocateUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnAllocateUserPhysicalPagesNuma =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR, DWORD) -> BOOL;
pub type FnApplicationRecoveryFinished = unsafe extern "system" fn(BOOL) -> ();
pub type FnApplicationRecoveryInProgress = unsafe extern "system" fn(PBOOL) -> HRESULT;
pub type FnAreFileApisANSI = unsafe extern "system" fn() -> BOOL;
pub type FnAssignProcessToJobObject = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnAttachConsole = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnBackupRead =
    unsafe extern "system" fn(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, *mut LPVOID) -> BOOL;
pub type FnBackupSeek =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, LPDWORD, LPDWORD, *mut LPVOID) -> BOOL;
pub type FnBackupWrite =
    unsafe extern "system" fn(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, *mut LPVOID) -> BOOL;
pub type FnBeep = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnBeginUpdateResourceA = unsafe extern "system" fn(LPCSTR, BOOL) -> HANDLE;
pub type FnBeginUpdateResourceW = unsafe extern "system" fn(LPCWSTR, BOOL) -> HANDLE;
pub type FnBindIoCompletionCallback =
    unsafe extern "system" fn(HANDLE, LPOVERLAPPED_COMPLETION_ROUTINE, ULONG) -> BOOL;
pub type FnBuildCommDCBA = unsafe extern "system" fn(LPCSTR, LPDCB) -> BOOL;
pub type FnBuildCommDCBAndTimeoutsA =
    unsafe extern "system" fn(LPCSTR, LPDCB, LPCOMMTIMEOUTS) -> BOOL;
pub type FnBuildCommDCBAndTimeoutsW =
    unsafe extern "system" fn(LPCWSTR, LPDCB, LPCOMMTIMEOUTS) -> BOOL;
pub type FnBuildCommDCBW = unsafe extern "system" fn(LPCWSTR, LPDCB) -> BOOL;
pub type FnCallNamedPipeA =
    unsafe extern "system" fn(LPCSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD) -> BOOL;
pub type FnCallNamedPipeW =
    unsafe extern "system" fn(LPCWSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD) -> BOOL;
pub type FnCallbackMayRunLong = unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> BOOL;
pub type FnCancelDeviceWakeupRequest = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCancelIo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCancelIoEx = unsafe extern "system" fn(HANDLE, LPOVERLAPPED) -> BOOL;
pub type FnCancelSynchronousIo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCancelThreadpoolIo = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnCancelTimerQueueTimer = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnCancelWaitableTimer = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnCeipIsOptedIn = unsafe extern "system" fn() -> BOOL;
pub type FnChangeTimerQueueTimer = unsafe extern "system" fn(HANDLE, HANDLE, ULONG, ULONG) -> BOOL;
pub type FnCheckNameLegalDOS8Dot3A =
    unsafe extern "system" fn(LPCSTR, LPSTR, DWORD, PBOOL, PBOOL) -> BOOL;
pub type FnCheckNameLegalDOS8Dot3W =
    unsafe extern "system" fn(LPCWSTR, LPSTR, DWORD, PBOOL, PBOOL) -> BOOL;
pub type FnCheckRemoteDebuggerPresent = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnCheckTokenCapability = unsafe extern "system" fn(HANDLE, PSID, PBOOL) -> BOOL;
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
pub type FnCommConfigDialogA = unsafe extern "system" fn(LPCSTR, HWND, LPCOMMCONFIG) -> BOOL;
pub type FnCommConfigDialogW = unsafe extern "system" fn(LPCWSTR, HWND, LPCOMMCONFIG) -> BOOL;
pub type FnCompareFileTime = unsafe extern "system" fn(*const FILETIME, *const FILETIME) -> LONG;
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
pub type FnCopyContext = unsafe extern "system" fn(PCONTEXT, DWORD, PCONTEXT) -> BOOL;
pub type FnCopyFile2 =
    unsafe extern "system" fn(PCWSTR, PCWSTR, *mut COPYFILE2_EXTENDED_PARAMETERS) -> HRESULT;
pub type FnCopyFileA = unsafe extern "system" fn(LPCSTR, LPCSTR, BOOL) -> BOOL;
pub type FnCopyFileExA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD) -> BOOL;
pub type FnCopyFileExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD) -> BOOL;
pub type FnCopyFileTransactedA = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    LPPROGRESS_ROUTINE,
    LPVOID,
    LPBOOL,
    DWORD,
    HANDLE,
) -> BOOL;
pub type FnCopyFileTransactedW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    LPPROGRESS_ROUTINE,
    LPVOID,
    LPBOOL,
    DWORD,
    HANDLE,
) -> BOOL;
pub type FnCopyFileW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, BOOL) -> BOOL;
pub type FnCreateActCtxA = unsafe extern "system" fn(PCACTCTXA) -> HANDLE;
pub type FnCreateActCtxW = unsafe extern "system" fn(PCACTCTXW) -> HANDLE;
pub type FnCreateBoundaryDescriptorA = unsafe extern "system" fn(LPCSTR, ULONG) -> HANDLE;
pub type FnCreateBoundaryDescriptorW = unsafe extern "system" fn(LPCWSTR, ULONG) -> HANDLE;
pub type FnCreateConsoleScreenBuffer =
    unsafe extern "system" fn(DWORD, DWORD, *const SECURITY_ATTRIBUTES, DWORD, LPVOID) -> HANDLE;
pub type FnCreateDirectoryA = unsafe extern "system" fn(LPCSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateDirectoryExA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateDirectoryExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateDirectoryTransactedA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES, HANDLE) -> BOOL;
pub type FnCreateDirectoryTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES, HANDLE) -> BOOL;
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
pub type FnCreateFileMappingA =
    unsafe extern "system" fn(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR) -> HANDLE;
pub type FnCreateFileMappingFromApp =
    unsafe extern "system" fn(HANDLE, PSECURITY_ATTRIBUTES, ULONG, ULONG64, PCWSTR) -> HANDLE;
pub type FnCreateFileMappingNumaA = unsafe extern "system" fn(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    DWORD,
    LPCSTR,
    DWORD,
) -> HANDLE;
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
pub type FnCreateFileTransactedA = unsafe extern "system" fn(
    LPCSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE,
    HANDLE,
    PUSHORT,
    PVOID,
) -> HANDLE;
pub type FnCreateFileTransactedW = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE,
    HANDLE,
    PUSHORT,
    PVOID,
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
pub type FnCreateHardLinkTransactedA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES, HANDLE) -> BOOL;
pub type FnCreateHardLinkTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES, HANDLE) -> ();
pub type FnCreateHardLinkW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES) -> BOOL;
pub type FnCreateIoCompletionPort =
    unsafe extern "system" fn(HANDLE, HANDLE, ULONG_PTR, DWORD) -> HANDLE;
pub type FnCreateJobObjectA = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCSTR) -> HANDLE;
pub type FnCreateJobObjectW = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR) -> HANDLE;
pub type FnCreateJobSet = unsafe extern "system" fn(ULONG, PJOB_SET_ARRAY, ULONG) -> BOOL;
pub type FnCreateMailslotA =
    unsafe extern "system" fn(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES) -> HANDLE;
pub type FnCreateMailslotW =
    unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES) -> HANDLE;
pub type FnCreateMemoryResourceNotification =
    unsafe extern "system" fn(MEMORY_RESOURCE_NOTIFICATION_TYPE) -> HANDLE;
pub type FnCreateMutexA = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR) -> HANDLE;
pub type FnCreateMutexExA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateMutexExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateMutexW = unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) -> HANDLE;
pub type FnCreateNamedPipeA = unsafe extern "system" fn(
    LPCSTR,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
) -> HANDLE;
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
pub type FnCreatePrivateNamespaceA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPVOID, LPCSTR) -> HANDLE;
pub type FnCreatePrivateNamespaceW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR) -> HANDLE;
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
pub type FnCreateSemaphoreA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR) -> HANDLE;
pub type FnCreateSemaphoreExA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateSemaphoreExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateSemaphoreW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR) -> HANDLE;
pub type FnCreateSymbolicLinkA = unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD) -> BOOLEAN;
pub type FnCreateSymbolicLinkTransactedA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD, HANDLE) -> BOOLEAN;
pub type FnCreateSymbolicLinkTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD, HANDLE) -> BOOLEAN;
pub type FnCreateSymbolicLinkW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD) -> BOOLEAN;
pub type FnCreateTapePartition = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD) -> DWORD;
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
pub type FnCreateToolhelp32Snapshot = unsafe extern "system" fn(DWORD, DWORD) -> HANDLE;
pub type FnCreateUmsCompletionList = unsafe extern "system" fn(*mut PUMS_COMPLETION_LIST) -> BOOL;
pub type FnCreateUmsThreadContext = unsafe extern "system" fn(*mut PUMS_CONTEXT) -> BOOL;
pub type FnCreateWaitableTimerA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR) -> HANDLE;
pub type FnCreateWaitableTimerExA =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateWaitableTimerExW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) -> HANDLE;
pub type FnCreateWaitableTimerW =
    unsafe extern "system" fn(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) -> HANDLE;
pub type FnDeactivateActCtx = unsafe extern "system" fn(DWORD, ULONG_PTR) -> BOOL;
pub type FnDebugActiveProcess = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnDebugActiveProcessStop = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnDebugBreak = unsafe extern "system" fn() -> ();
pub type FnDebugBreakProcess = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDebugSetProcessKillOnExit = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnDecodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnDecodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnDefineDosDeviceA = unsafe extern "system" fn(DWORD, LPCSTR, LPCSTR) -> BOOL;
pub type FnDefineDosDeviceW = unsafe extern "system" fn(DWORD, LPCWSTR, LPCWSTR) -> BOOL;
pub type FnDeleteAtom = unsafe extern "system" fn(ATOM) -> ATOM;
pub type FnDeleteBoundaryDescriptor = unsafe extern "system" fn(HANDLE) -> ();
pub type FnDeleteCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnDeleteFiber = unsafe extern "system" fn(LPVOID) -> ();
pub type FnDeleteFileA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnDeleteFileTransactedA = unsafe extern "system" fn(LPCSTR, HANDLE) -> BOOL;
pub type FnDeleteFileTransactedW = unsafe extern "system" fn(LPCWSTR, HANDLE) -> BOOL;
pub type FnDeleteFileW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnDeleteProcThreadAttributeList =
    unsafe extern "system" fn(LPPROC_THREAD_ATTRIBUTE_LIST) -> ();
pub type FnDeleteSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER) -> BOOL;
pub type FnDeleteTimerQueue = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDeleteTimerQueueEx = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;
pub type FnDeleteTimerQueueTimer = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> BOOL;
pub type FnDeleteUmsCompletionList = unsafe extern "system" fn(PUMS_COMPLETION_LIST) -> BOOL;
pub type FnDeleteUmsThreadContext = unsafe extern "system" fn(PUMS_CONTEXT) -> BOOL;
pub type FnDeleteVolumeMountPointA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnDeleteVolumeMountPointW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnDequeueUmsCompletionListItems =
    unsafe extern "system" fn(PUMS_COMPLETION_LIST, DWORD, *mut PUMS_CONTEXT) -> BOOL;
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
pub type FnDisableThreadProfiling = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnDisassociateCurrentThreadFromCallback =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> ();
pub type FnDiscardVirtualMemory = unsafe extern "system" fn(PVOID, SIZE_T) -> DWORD;
pub type FnDisconnectNamedPipe = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDnsHostnameToComputerNameA = unsafe extern "system" fn(LPCSTR, LPCSTR, LPDWORD) -> BOOL;
pub type FnDnsHostnameToComputerNameExW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, LPDWORD) -> BOOL;
pub type FnDnsHostnameToComputerNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, LPDWORD) -> BOOL;
pub type FnDosDateTimeToFileTime = unsafe extern "system" fn(WORD, WORD, LPFILETIME) -> BOOL;
pub type FnDuplicateHandle =
    unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) -> BOOL;
pub type FnEnableThreadProfiling =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD64, *mut HANDLE) -> BOOL;
pub type FnEncodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnEncodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnEndUpdateResourceA = unsafe extern "system" fn(HANDLE, BOOL) -> BOOL;
pub type FnEndUpdateResourceW = unsafe extern "system" fn(HANDLE, BOOL) -> BOOL;
pub type FnEnterCriticalSection = unsafe extern "system" fn(LPCRITICAL_SECTION) -> ();
pub type FnEnterSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER, DWORD) -> BOOL;
pub type FnEnterUmsSchedulingMode = unsafe extern "system" fn(PUMS_SCHEDULER_STARTUP_INFO) -> BOOL;
pub type FnEnumCalendarInfoA =
    unsafe extern "system" fn(CALINFO_ENUMPROCA, LCID, CALID, CALTYPE) -> BOOL;
pub type FnEnumCalendarInfoExA =
    unsafe extern "system" fn(CALINFO_ENUMPROCEXA, LCID, CALID, CALTYPE) -> BOOL;
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
pub type FnEnumDateFormatsA = unsafe extern "system" fn(DATEFMT_ENUMPROCA, LCID, DWORD) -> BOOL;
pub type FnEnumDateFormatsExA = unsafe extern "system" fn(DATEFMT_ENUMPROCEXA, LCID, DWORD) -> BOOL;
pub type FnEnumDateFormatsExEx =
    unsafe extern "system" fn(DATEFMT_ENUMPROCEXEX, LPCWSTR, DWORD, LPARAM) -> BOOL;
pub type FnEnumDateFormatsExW = unsafe extern "system" fn(DATEFMT_ENUMPROCEXW, LCID, DWORD) -> BOOL;
pub type FnEnumDateFormatsW = unsafe extern "system" fn(DATEFMT_ENUMPROCW, LCID, DWORD) -> BOOL;
pub type FnEnumLanguageGroupLocalesA =
    unsafe extern "system" fn(LANGGROUPLOCALE_ENUMPROCA, LGRPID, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumLanguageGroupLocalesW =
    unsafe extern "system" fn(LANGGROUPLOCALE_ENUMPROCW, LGRPID, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumResourceLanguagesA =
    unsafe extern "system" fn(HMODULE, LPCSTR, LPCSTR, ENUMRESLANGPROCA, LONG_PTR) -> BOOL;
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
pub type FnEnumResourceLanguagesW =
    unsafe extern "system" fn(HMODULE, LPCWSTR, LPCWSTR, ENUMRESLANGPROCW, LONG_PTR) -> BOOL;
pub type FnEnumResourceNamesA =
    unsafe extern "system" fn(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR) -> BOOL;
pub type FnEnumResourceNamesExA =
    unsafe extern "system" fn(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceNamesExW =
    unsafe extern "system" fn(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceNamesW =
    unsafe extern "system" fn(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR) -> BOOL;
pub type FnEnumResourceTypesA =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCA, LONG_PTR) -> BOOL;
pub type FnEnumResourceTypesExA =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCA, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceTypesExW =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCW, LONG_PTR, DWORD, LANGID) -> BOOL;
pub type FnEnumResourceTypesW =
    unsafe extern "system" fn(HMODULE, ENUMRESTYPEPROCW, LONG_PTR) -> BOOL;
pub type FnEnumSystemCodePagesA = unsafe extern "system" fn(CODEPAGE_ENUMPROCA, DWORD) -> BOOL;
pub type FnEnumSystemCodePagesW = unsafe extern "system" fn(CODEPAGE_ENUMPROCW, DWORD) -> BOOL;
pub type FnEnumSystemFirmwareTables = unsafe extern "system" fn(DWORD, PVOID, DWORD) -> UINT;
pub type FnEnumSystemGeoID = unsafe extern "system" fn(GEOCLASS, GEOID, GEO_ENUMPROC) -> BOOL;
pub type FnEnumSystemLanguageGroupsA =
    unsafe extern "system" fn(LANGUAGEGROUP_ENUMPROCA, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumSystemLanguageGroupsW =
    unsafe extern "system" fn(LANGUAGEGROUP_ENUMPROCW, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumSystemLocalesA = unsafe extern "system" fn(LOCALE_ENUMPROCA, DWORD) -> BOOL;
pub type FnEnumSystemLocalesEx =
    unsafe extern "system" fn(LOCALE_ENUMPROCEX, DWORD, LPARAM, LPVOID) -> BOOL;
pub type FnEnumSystemLocalesW = unsafe extern "system" fn(LOCALE_ENUMPROCW, DWORD) -> BOOL;
pub type FnEnumTimeFormatsA = unsafe extern "system" fn(TIMEFMT_ENUMPROCA, LCID, DWORD) -> BOOL;
pub type FnEnumTimeFormatsEx =
    unsafe extern "system" fn(TIMEFMT_ENUMPROCEX, LPCWSTR, DWORD, LPARAM) -> BOOL;
pub type FnEnumTimeFormatsW = unsafe extern "system" fn(TIMEFMT_ENUMPROCW, LCID, DWORD) -> BOOL;
pub type FnEnumUILanguagesA =
    unsafe extern "system" fn(UILANGUAGE_ENUMPROCA, DWORD, LONG_PTR) -> BOOL;
pub type FnEnumUILanguagesW =
    unsafe extern "system" fn(UILANGUAGE_ENUMPROCW, DWORD, LONG_PTR) -> BOOL;
pub type FnEraseTape = unsafe extern "system" fn(HANDLE, DWORD, BOOL) -> DWORD;
pub type FnEscapeCommFunction = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnExecuteUmsThread = unsafe extern "system" fn(PUMS_CONTEXT) -> BOOL;
pub type FnExitProcess = unsafe extern "system" fn(UINT) -> ();
pub type FnExitThread = unsafe extern "system" fn(DWORD) -> ();
pub type FnExpandEnvironmentStringsA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnExpandEnvironmentStringsW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnFatalAppExitA = unsafe extern "system" fn(UINT, LPCSTR) -> ();
pub type FnFatalAppExitW = unsafe extern "system" fn(UINT, LPCWSTR) -> ();
pub type FnFatalExit = unsafe extern "system" fn(c_int) -> ();
pub type FnFileTimeToDosDateTime =
    unsafe extern "system" fn(*const FILETIME, LPWORD, LPWORD) -> BOOL;
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
pub type FnFindActCtxSectionStringA = unsafe extern "system" fn(
    DWORD,
    *const GUID,
    ULONG,
    LPCSTR,
    PACTCTX_SECTION_KEYED_DATA,
) -> BOOL;
pub type FnFindActCtxSectionStringW = unsafe extern "system" fn(
    DWORD,
    *const GUID,
    ULONG,
    LPCWSTR,
    PACTCTX_SECTION_KEYED_DATA,
) -> BOOL;
pub type FnFindAtomA = unsafe extern "system" fn(LPCSTR) -> ATOM;
pub type FnFindAtomW = unsafe extern "system" fn(LPCWSTR) -> ATOM;
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
pub type FnFindFirstFileNameTransactedW =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPDWORD, PWSTR, HANDLE) -> HANDLE;
pub type FnFindFirstFileNameW = unsafe extern "system" fn(LPCWSTR, DWORD, LPDWORD, PWSTR) -> HANDLE;
pub type FnFindFirstFileTransactedA = unsafe extern "system" fn(
    LPCSTR,
    FINDEX_INFO_LEVELS,
    LPVOID,
    FINDEX_SEARCH_OPS,
    LPVOID,
    DWORD,
    HANDLE,
) -> HANDLE;
pub type FnFindFirstFileTransactedW = unsafe extern "system" fn(
    LPCWSTR,
    FINDEX_INFO_LEVELS,
    LPVOID,
    FINDEX_SEARCH_OPS,
    LPVOID,
    DWORD,
    HANDLE,
) -> HANDLE;
pub type FnFindFirstFileW = unsafe extern "system" fn(LPCWSTR, LPWIN32_FIND_DATAW) -> HANDLE;
pub type FnFindFirstStreamTransactedW =
    unsafe extern "system" fn(LPCWSTR, STREAM_INFO_LEVELS, LPVOID, DWORD, HANDLE) -> HANDLE;
pub type FnFindFirstStreamW =
    unsafe extern "system" fn(LPCWSTR, STREAM_INFO_LEVELS, LPVOID, DWORD) -> HANDLE;
pub type FnFindFirstVolumeA = unsafe extern "system" fn(LPSTR, DWORD) -> HANDLE;
pub type FnFindFirstVolumeMountPointA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> HANDLE;
pub type FnFindFirstVolumeMountPointW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> HANDLE;
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
pub type FnFindNextVolumeA = unsafe extern "system" fn(HANDLE, LPSTR, DWORD) -> BOOL;
pub type FnFindNextVolumeMountPointA = unsafe extern "system" fn(HANDLE, LPSTR, DWORD) -> BOOL;
pub type FnFindNextVolumeMountPointW = unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> BOOL;
pub type FnFindNextVolumeW = unsafe extern "system" fn(HANDLE, LPWSTR, DWORD) -> BOOL;
pub type FnFindResourceA = unsafe extern "system" fn(HMODULE, LPCSTR, LPCSTR) -> HRSRC;
pub type FnFindResourceExA = unsafe extern "system" fn(HMODULE, LPCSTR, LPCSTR, WORD) -> HRSRC;
pub type FnFindResourceExW = unsafe extern "system" fn(HMODULE, LPCWSTR, LPCWSTR, WORD) -> HRSRC;
pub type FnFindResourceW = unsafe extern "system" fn(HMODULE, LPCWSTR, LPCWSTR) -> HRSRC;
pub type FnFindStringOrdinal =
    unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPCWSTR, c_int, BOOL) -> c_int;
pub type FnFindVolumeClose = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFindVolumeMountPointClose = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlsAlloc = unsafe extern "system" fn(PFLS_CALLBACK_FUNCTION) -> DWORD;
pub type FnFlsFree = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnFlsGetValue = unsafe extern "system" fn(DWORD) -> PVOID;
pub type FnFlsSetValue = unsafe extern "system" fn(DWORD, PVOID) -> BOOL;
pub type FnFlushConsoleInputBuffer = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlushFileBuffers = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnFlushInstructionCache = unsafe extern "system" fn(HANDLE, LPCVOID, SIZE_T) -> BOOL;
pub type FnFlushProcessWriteBuffers = unsafe extern "system" fn() -> ();
pub type FnFlushViewOfFile = unsafe extern "system" fn(LPCVOID, SIZE_T) -> BOOL;
pub type FnFoldStringA = unsafe extern "system" fn(DWORD, LPCSTR, c_int, LPSTR, c_int) -> c_int;
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
pub type FnFreeMemoryJobObject = unsafe extern "system" fn(*mut VOID) -> ();
pub type FnFreeResource = unsafe extern "system" fn(HGLOBAL) -> BOOL;
pub type FnFreeUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnGenerateConsoleCtrlEvent = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnGetACP = unsafe extern "system" fn() -> UINT;
pub type FnGetActiveProcessorCount = unsafe extern "system" fn(WORD) -> DWORD;
pub type FnGetActiveProcessorGroupCount = unsafe extern "system" fn() -> WORD;
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
pub type FnGetAtomNameA = unsafe extern "system" fn(ATOM, LPSTR, c_int) -> UINT;
pub type FnGetAtomNameW = unsafe extern "system" fn(ATOM, LPWSTR, c_int) -> UINT;
pub type FnGetBinaryTypeA = unsafe extern "system" fn(LPCSTR, LPDWORD) -> BOOL;
pub type FnGetBinaryTypeW = unsafe extern "system" fn(LPCWSTR, LPDWORD) -> BOOL;
pub type FnGetCPInfo = unsafe extern "system" fn(UINT, LPCPINFO) -> BOOL;
pub type FnGetCPInfoExA = unsafe extern "system" fn(UINT, DWORD, LPCPINFOEXA) -> BOOL;
pub type FnGetCPInfoExW = unsafe extern "system" fn(UINT, DWORD, LPCPINFOEXW) -> BOOL;
pub type FnGetCachedSigningLevel =
    unsafe extern "system" fn(HANDLE, PULONG, PULONG, PUCHAR, PULONG, PULONG) -> BOOL;
pub type FnGetCalendarInfoA =
    unsafe extern "system" fn(LCID, CALID, CALTYPE, LPSTR, c_int, LPDWORD) -> c_int;
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
pub type FnGetCompressedFileSizeTransactedA =
    unsafe extern "system" fn(LPCSTR, LPDWORD, HANDLE) -> DWORD;
pub type FnGetCompressedFileSizeTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPDWORD, HANDLE) -> ();
pub type FnGetCompressedFileSizeW = unsafe extern "system" fn(LPCWSTR, LPDWORD) -> DWORD;
pub type FnGetComputerNameA = unsafe extern "system" fn(LPSTR, LPDWORD) -> BOOL;
pub type FnGetComputerNameExA =
    unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD) -> BOOL;
pub type FnGetComputerNameExW =
    unsafe extern "system" fn(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD) -> BOOL;
pub type FnGetComputerNameW = unsafe extern "system" fn(LPWSTR, LPDWORD) -> BOOL;
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
pub type FnGetCurrencyFormatA =
    unsafe extern "system" fn(LCID, DWORD, LPCSTR, *const CURRENCYFMTA, LPSTR, c_int) -> c_int;
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
pub type FnGetCurrentUmsThread = unsafe extern "system" fn() -> PUMS_CONTEXT;
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
pub type FnGetDefaultCommConfigA = unsafe extern "system" fn(LPCSTR, LPCOMMCONFIG, LPDWORD) -> BOOL;
pub type FnGetDefaultCommConfigW =
    unsafe extern "system" fn(LPCWSTR, LPCOMMCONFIG, LPDWORD) -> BOOL;
pub type FnGetDevicePowerState = unsafe extern "system" fn(HANDLE, *mut BOOL) -> BOOL;
pub type FnGetDiskFreeSpaceA =
    unsafe extern "system" fn(LPCSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetDiskFreeSpaceExA =
    unsafe extern "system" fn(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER) -> BOOL;
pub type FnGetDiskFreeSpaceExW =
    unsafe extern "system" fn(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER) -> BOOL;
pub type FnGetDiskFreeSpaceW =
    unsafe extern "system" fn(LPCWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetDllDirectoryA = unsafe extern "system" fn(DWORD, LPSTR) -> DWORD;
pub type FnGetDllDirectoryW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;
pub type FnGetDriveTypeA = unsafe extern "system" fn(LPCSTR) -> UINT;
pub type FnGetDriveTypeW = unsafe extern "system" fn(LPCWSTR) -> UINT;
pub type FnGetDurationFormat = unsafe extern "system" fn(
    LCID,
    DWORD,
    *const SYSTEMTIME,
    ULONGLONG,
    LPCWSTR,
    LPWSTR,
    c_int,
) -> c_int;
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
pub type FnGetFileAttributesTransactedA =
    unsafe extern "system" fn(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID, HANDLE) -> BOOL;
pub type FnGetFileAttributesTransactedW =
    unsafe extern "system" fn(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID, HANDLE) -> BOOL;
pub type FnGetFileAttributesW = unsafe extern "system" fn(LPCWSTR) -> DWORD;
pub type FnGetFileBandwidthReservation =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPBOOL, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetFileInformationByHandle =
    unsafe extern "system" fn(HANDLE, LPBY_HANDLE_FILE_INFORMATION) -> BOOL;
pub type FnGetFileInformationByHandleEx =
    unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnGetFileMUIInfo =
    unsafe extern "system" fn(DWORD, PCWSTR, PFILEMUIINFO, *mut DWORD) -> BOOL;
pub type FnGetFileMUIPath =
    unsafe extern "system" fn(DWORD, PCWSTR, PWSTR, PULONG, PWSTR, PULONG, PULONGLONG) -> BOOL;
pub type FnGetFileSize = unsafe extern "system" fn(HANDLE, LPDWORD) -> DWORD;
pub type FnGetFileSizeEx = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> BOOL;
pub type FnGetFileTime =
    unsafe extern "system" fn(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetFileType = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetFinalPathNameByHandleA =
    unsafe extern "system" fn(HANDLE, LPSTR, DWORD, DWORD) -> DWORD;
pub type FnGetFinalPathNameByHandleW =
    unsafe extern "system" fn(HANDLE, LPWSTR, DWORD, DWORD) -> DWORD;
pub type FnGetFirmwareEnvironmentVariableA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, PVOID, DWORD) -> DWORD;
pub type FnGetFirmwareEnvironmentVariableExA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, PVOID, DWORD, PDWORD) -> DWORD;
pub type FnGetFirmwareEnvironmentVariableExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, PVOID, DWORD, PDWORD) -> DWORD;
pub type FnGetFirmwareEnvironmentVariableW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, PVOID, DWORD) -> DWORD;
pub type FnGetFirmwareType = unsafe extern "system" fn(PFIRMWARE_TYPE) -> BOOL;
pub type FnGetFullPathNameA = unsafe extern "system" fn(LPCSTR, DWORD, LPSTR, *mut LPSTR) -> DWORD;
pub type FnGetFullPathNameTransactedA =
    unsafe extern "system" fn(LPCSTR, DWORD, LPSTR, *mut LPSTR, HANDLE) -> DWORD;
pub type FnGetFullPathNameTransactedW =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPWSTR, *mut LPWSTR, HANDLE) -> ();
pub type FnGetFullPathNameW =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPWSTR, *mut LPWSTR) -> DWORD;
pub type FnGetGeoInfoA = unsafe extern "system" fn(GEOID, GEOTYPE, LPSTR, c_int, LANGID) -> c_int;
pub type FnGetGeoInfoW = unsafe extern "system" fn(GEOID, GEOTYPE, LPWSTR, c_int, LANGID) -> c_int;
pub type FnGetHandleInformation = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnGetLargePageMinimum = unsafe extern "system" fn() -> SIZE_T;
pub type FnGetLargestConsoleWindowSize = unsafe extern "system" fn(HANDLE) -> COORD;
pub type FnGetLastError = unsafe extern "system" fn() -> DWORD;
pub type FnGetLocalTime = unsafe extern "system" fn(LPSYSTEMTIME) -> ();
pub type FnGetLocaleInfoA = unsafe extern "system" fn(LCID, LCTYPE, LPSTR, c_int) -> c_int;
pub type FnGetLocaleInfoEx = unsafe extern "system" fn(LPCWSTR, LCTYPE, LPWSTR, c_int) -> c_int;
pub type FnGetLocaleInfoW = unsafe extern "system" fn(LCID, LCTYPE, LPWSTR, c_int) -> c_int;
pub type FnGetLogicalDriveStringsA = unsafe extern "system" fn(DWORD, LPSTR) -> DWORD;
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
pub type FnGetLongPathNameTransactedA =
    unsafe extern "system" fn(LPCSTR, LPSTR, DWORD, HANDLE) -> DWORD;
pub type FnGetLongPathNameTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD, HANDLE) -> DWORD;
pub type FnGetLongPathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetMailslotInfo =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetMaximumProcessorCount = unsafe extern "system" fn(WORD) -> DWORD;
pub type FnGetMaximumProcessorGroupCount = unsafe extern "system" fn() -> WORD;
pub type FnGetMemoryErrorHandlingCapabilities = unsafe extern "system" fn(PULONG) -> BOOL;
pub type FnGetModuleFileNameA = unsafe extern "system" fn(HMODULE, LPSTR, DWORD) -> DWORD;
pub type FnGetModuleFileNameW = unsafe extern "system" fn(HMODULE, LPWSTR, DWORD) -> DWORD;
pub type FnGetModuleHandleA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
pub type FnGetModuleHandleExA = unsafe extern "system" fn(DWORD, LPCSTR, *mut HMODULE) -> BOOL;
pub type FnGetModuleHandleExW = unsafe extern "system" fn(DWORD, LPCWSTR, *mut HMODULE) -> BOOL;
pub type FnGetModuleHandleW = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
pub type FnGetNLSVersion = unsafe extern "system" fn(NLS_FUNCTION, LCID, LPNLSVERSIONINFO) -> BOOL;
pub type FnGetNLSVersionEx =
    unsafe extern "system" fn(NLS_FUNCTION, LPCWSTR, LPNLSVERSIONINFOEX) -> BOOL;
pub type FnGetNamedPipeClientComputerNameA =
    unsafe extern "system" fn(HANDLE, LPSTR, ULONG) -> BOOL;
pub type FnGetNamedPipeClientComputerNameW =
    unsafe extern "system" fn(HANDLE, LPWSTR, ULONG) -> BOOL;
pub type FnGetNamedPipeClientProcessId = unsafe extern "system" fn(HANDLE, PULONG) -> BOOL;
pub type FnGetNamedPipeClientSessionId = unsafe extern "system" fn(HANDLE, PULONG) -> BOOL;
pub type FnGetNamedPipeHandleStateA =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD) -> BOOL;
pub type FnGetNamedPipeHandleStateW =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD) -> BOOL;
pub type FnGetNamedPipeInfo =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnGetNamedPipeServerProcessId = unsafe extern "system" fn(HANDLE, PULONG) -> BOOL;
pub type FnGetNamedPipeServerSessionId = unsafe extern "system" fn(HANDLE, PULONG) -> BOOL;
pub type FnGetNativeSystemInfo = unsafe extern "system" fn(LPSYSTEM_INFO) -> ();
pub type FnGetNextUmsListItem = unsafe extern "system" fn(PUMS_CONTEXT) -> PUMS_CONTEXT;
pub type FnGetNumaAvailableMemoryNode = unsafe extern "system" fn(UCHAR, PULONGLONG) -> BOOL;
pub type FnGetNumaAvailableMemoryNodeEx = unsafe extern "system" fn(USHORT, PULONGLONG) -> BOOL;
pub type FnGetNumaHighestNodeNumber = unsafe extern "system" fn(PULONG) -> BOOL;
pub type FnGetNumaNodeNumberFromHandle = unsafe extern "system" fn(HANDLE, PUSHORT) -> BOOL;
pub type FnGetNumaNodeProcessorMask = unsafe extern "system" fn(UCHAR, PULONGLONG) -> BOOL;
pub type FnGetNumaNodeProcessorMaskEx = unsafe extern "system" fn(USHORT, PGROUP_AFFINITY) -> BOOL;
pub type FnGetNumaProcessorNode = unsafe extern "system" fn(UCHAR, PUCHAR) -> BOOL;
pub type FnGetNumaProcessorNodeEx = unsafe extern "system" fn(PPROCESSOR_NUMBER, PUSHORT) -> BOOL;
pub type FnGetNumaProximityNode = unsafe extern "system" fn(ULONG, PUCHAR) -> BOOL;
pub type FnGetNumaProximityNodeEx = unsafe extern "system" fn(ULONG, PUSHORT) -> BOOL;
pub type FnGetNumberFormatA =
    unsafe extern "system" fn(LCID, DWORD, LPCSTR, *const NUMBERFMTA, LPSTR, c_int) -> c_int;
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
pub type FnGetPhysicallyInstalledSystemMemory = unsafe extern "system" fn(PULONGLONG) -> BOOL;
pub type FnGetPriorityClass = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetPrivateProfileIntA = unsafe extern "system" fn(LPCSTR, LPCSTR, INT, LPCSTR) -> UINT;
pub type FnGetPrivateProfileIntW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, INT, LPCWSTR) -> UINT;
pub type FnGetPrivateProfileSectionA =
    unsafe extern "system" fn(LPCSTR, LPSTR, DWORD, LPCSTR) -> DWORD;
pub type FnGetPrivateProfileSectionNamesA =
    unsafe extern "system" fn(LPSTR, DWORD, LPCSTR) -> DWORD;
pub type FnGetPrivateProfileSectionNamesW =
    unsafe extern "system" fn(LPWSTR, DWORD, LPCWSTR) -> DWORD;
pub type FnGetPrivateProfileSectionW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD, LPCWSTR) -> DWORD;
pub type FnGetPrivateProfileStringA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR) -> DWORD;
pub type FnGetPrivateProfileStringW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR) -> DWORD;
pub type FnGetPrivateProfileStructA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR) -> BOOL;
pub type FnGetPrivateProfileStructW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR) -> BOOL;
pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;
pub type FnGetProcessAffinityMask =
    unsafe extern "system" fn(HANDLE, PDWORD_PTR, PDWORD_PTR) -> BOOL;
pub type FnGetProcessDEPPolicy = unsafe extern "system" fn(HANDLE, LPDWORD, PBOOL) -> BOOL;
pub type FnGetProcessGroupAffinity = unsafe extern "system" fn(HANDLE, PUSHORT, PUSHORT) -> BOOL;
pub type FnGetProcessHandleCount = unsafe extern "system" fn(HANDLE, PDWORD) -> BOOL;
pub type FnGetProcessHeap = unsafe extern "system" fn() -> HANDLE;
pub type FnGetProcessHeaps = unsafe extern "system" fn(DWORD, PHANDLE) -> DWORD;
pub type FnGetProcessId = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetProcessIdOfThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnGetProcessInformation =
    unsafe extern "system" fn(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnGetProcessIoCounters = unsafe extern "system" fn(HANDLE, PIO_COUNTERS) -> BOOL;
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
pub type FnGetProfileIntA = unsafe extern "system" fn(LPCSTR, LPCSTR, INT) -> UINT;
pub type FnGetProfileIntW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, INT) -> UINT;
pub type FnGetProfileSectionA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnGetProfileSectionW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetProfileStringA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnGetProfileStringW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetQueuedCompletionStatus =
    unsafe extern "system" fn(HANDLE, LPDWORD, PULONG_PTR, *mut LPOVERLAPPED, DWORD) -> BOOL;
pub type FnGetQueuedCompletionStatusEx =
    unsafe extern "system" fn(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL) -> BOOL;
pub type FnGetShortPathNameA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnGetShortPathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnGetStartupInfoA = unsafe extern "system" fn(LPSTARTUPINFOA) -> ();
pub type FnGetStartupInfoW = unsafe extern "system" fn(LPSTARTUPINFOW) -> ();
pub type FnGetStdHandle = unsafe extern "system" fn(DWORD) -> HANDLE;
pub type FnGetStringScripts =
    unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnGetStringTypeA = unsafe extern "system" fn(LCID, DWORD, LPCSTR, c_int, LPWORD) -> BOOL;
pub type FnGetStringTypeExA = unsafe extern "system" fn(LCID, DWORD, LPCSTR, c_int, LPWORD) -> BOOL;
pub type FnGetStringTypeExW = unsafe extern "system" fn(LCID, DWORD, LPCWCH, c_int, LPWORD) -> BOOL;
pub type FnGetStringTypeW = unsafe extern "system" fn(DWORD, LPCWCH, c_int, LPWORD) -> BOOL;
pub type FnGetSystemDEPPolicy = unsafe extern "system" fn() -> DEP_SYSTEM_POLICY_TYPE;
pub type FnGetSystemDefaultLCID = unsafe extern "system" fn() -> LCID;
pub type FnGetSystemDefaultLangID = unsafe extern "system" fn() -> LANGID;
pub type FnGetSystemDefaultLocaleName = unsafe extern "system" fn(LPWSTR, c_int) -> c_int;
pub type FnGetSystemDefaultUILanguage = unsafe extern "system" fn() -> LANGID;
pub type FnGetSystemDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetSystemFileCacheSize = unsafe extern "system" fn(PSIZE_T, PSIZE_T, PDWORD) -> BOOL;
pub type FnGetSystemFirmwareTable = unsafe extern "system" fn(DWORD, DWORD, PVOID, DWORD) -> UINT;
pub type FnGetSystemInfo = unsafe extern "system" fn(LPSYSTEM_INFO) -> ();
pub type FnGetSystemPowerStatus = unsafe extern "system" fn(LPSYSTEM_POWER_STATUS) -> BOOL;
pub type FnGetSystemPreferredUILanguages =
    unsafe extern "system" fn(DWORD, PULONG, PZZWSTR, PULONG) -> BOOL;
pub type FnGetSystemRegistryQuota = unsafe extern "system" fn(PDWORD, PDWORD) -> BOOL;
pub type FnGetSystemTime = unsafe extern "system" fn(LPSYSTEMTIME) -> ();
pub type FnGetSystemTimeAdjustment = unsafe extern "system" fn(PDWORD, PDWORD, PBOOL) -> BOOL;
pub type FnGetSystemTimeAsFileTime = unsafe extern "system" fn(LPFILETIME) -> ();
pub type FnGetSystemTimePreciseAsFileTime = unsafe extern "system" fn(LPFILETIME) -> ();
pub type FnGetSystemTimes = unsafe extern "system" fn(LPFILETIME, LPFILETIME, LPFILETIME) -> BOOL;
pub type FnGetSystemWindowsDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemWindowsDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetSystemWow64DirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetSystemWow64DirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetTapeParameters = unsafe extern "system" fn(HANDLE, DWORD, LPDWORD, LPVOID) -> DWORD;
pub type FnGetTapePosition =
    unsafe extern "system" fn(HANDLE, DWORD, LPDWORD, LPDWORD, LPDWORD) -> DWORD;
pub type FnGetTapeStatus = unsafe extern "system" fn(HANDLE) -> DWORD;
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
pub type FnGetThreadSelectorEntry = unsafe extern "system" fn(HANDLE, DWORD, LPLDT_ENTRY) -> BOOL;
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
pub type FnGetUILanguageInfo =
    unsafe extern "system" fn(DWORD, PCZZWSTR, PZZWSTR, PDWORD, PDWORD) -> BOOL;
pub type FnGetUmsCompletionListEvent =
    unsafe extern "system" fn(PUMS_COMPLETION_LIST, PHANDLE) -> BOOL;
pub type FnGetUmsSystemThreadInformation =
    unsafe extern "system" fn(HANDLE, PUMS_SYSTEM_THREAD_INFORMATION) -> BOOL;
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
pub type FnGetVolumeNameForVolumeMountPointA =
    unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> BOOL;
pub type FnGetVolumeNameForVolumeMountPointW =
    unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> BOOL;
pub type FnGetVolumePathNameA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> BOOL;
pub type FnGetVolumePathNameW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> BOOL;
pub type FnGetVolumePathNamesForVolumeNameA =
    unsafe extern "system" fn(LPCSTR, LPCH, DWORD, PDWORD) -> BOOL;
pub type FnGetVolumePathNamesForVolumeNameW =
    unsafe extern "system" fn(LPCWSTR, LPWCH, DWORD, PDWORD) -> BOOL;
pub type FnGetWindowsDirectoryA = unsafe extern "system" fn(LPSTR, UINT) -> UINT;
pub type FnGetWindowsDirectoryW = unsafe extern "system" fn(LPWSTR, UINT) -> UINT;
pub type FnGetWriteWatch =
    unsafe extern "system" fn(DWORD, PVOID, SIZE_T, *mut PVOID, *mut ULONG_PTR, LPDWORD) -> UINT;
pub type FnGlobalAddAtomA = unsafe extern "system" fn(LPCSTR) -> ATOM;
pub type FnGlobalAddAtomExA = unsafe extern "system" fn(LPCSTR, DWORD) -> ATOM;
pub type FnGlobalAddAtomExW = unsafe extern "system" fn(LPCWSTR, DWORD) -> ATOM;
pub type FnGlobalAddAtomW = unsafe extern "system" fn(LPCWSTR) -> ATOM;
pub type FnGlobalAlloc = unsafe extern "system" fn(UINT, SIZE_T) -> HGLOBAL;
pub type FnGlobalCompact = unsafe extern "system" fn(DWORD) -> SIZE_T;
pub type FnGlobalDeleteAtom = unsafe extern "system" fn(ATOM) -> ATOM;
pub type FnGlobalFindAtomA = unsafe extern "system" fn(LPCSTR) -> ATOM;
pub type FnGlobalFindAtomW = unsafe extern "system" fn(LPCWSTR) -> ATOM;
pub type FnGlobalFix = unsafe extern "system" fn(HGLOBAL) -> ();
pub type FnGlobalFlags = unsafe extern "system" fn(HGLOBAL) -> UINT;
pub type FnGlobalFree = unsafe extern "system" fn(HGLOBAL) -> HGLOBAL;
pub type FnGlobalGetAtomNameA = unsafe extern "system" fn(ATOM, LPSTR, c_int) -> UINT;
pub type FnGlobalGetAtomNameW = unsafe extern "system" fn(ATOM, LPWSTR, c_int) -> UINT;
pub type FnGlobalHandle = unsafe extern "system" fn(LPCVOID) -> HGLOBAL;
pub type FnGlobalLock = unsafe extern "system" fn(HGLOBAL) -> LPVOID;
pub type FnGlobalMemoryStatus = unsafe extern "system" fn(LPMEMORYSTATUS) -> ();
pub type FnGlobalMemoryStatusEx = unsafe extern "system" fn(LPMEMORYSTATUSEX) -> BOOL;
pub type FnGlobalReAlloc = unsafe extern "system" fn(HGLOBAL, SIZE_T, UINT) -> HGLOBAL;
pub type FnGlobalSize = unsafe extern "system" fn(HGLOBAL) -> SIZE_T;
pub type FnGlobalUnWire = unsafe extern "system" fn(HGLOBAL) -> BOOL;
pub type FnGlobalUnfix = unsafe extern "system" fn(HGLOBAL) -> ();
pub type FnGlobalUnlock = unsafe extern "system" fn(HGLOBAL) -> BOOL;
pub type FnGlobalWire = unsafe extern "system" fn(HGLOBAL) -> LPVOID;
pub type FnHeap32First = unsafe extern "system" fn(LPHEAPENTRY32, DWORD, ULONG_PTR) -> BOOL;
pub type FnHeap32ListFirst = unsafe extern "system" fn(HANDLE, LPHEAPLIST32) -> BOOL;
pub type FnHeap32ListNext = unsafe extern "system" fn(HANDLE, LPHEAPLIST32) -> BOOL;
pub type FnHeap32Next = unsafe extern "system" fn(LPHEAPENTRY32) -> BOOL;
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
pub type FnInitAtomTable = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnInitOnceBeginInitialize =
    unsafe extern "system" fn(LPINIT_ONCE, DWORD, PBOOL, *mut LPVOID) -> BOOL;
pub type FnInitOnceComplete = unsafe extern "system" fn(LPINIT_ONCE, DWORD, LPVOID) -> BOOL;
pub type FnInitOnceExecuteOnce =
    unsafe extern "system" fn(PINIT_ONCE, PINIT_ONCE_FN, PVOID, *mut LPVOID) -> BOOL;
pub type FnInitOnceInitialize = unsafe extern "system" fn(PINIT_ONCE) -> ();
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
pub type FnInitializeSListHead = unsafe extern "system" fn(PSLIST_HEADER) -> ();
pub type FnInitializeSRWLock = unsafe extern "system" fn(PSRWLOCK) -> ();
pub type FnInitializeSynchronizationBarrier =
    unsafe extern "system" fn(LPSYNCHRONIZATION_BARRIER, LONG, LONG) -> BOOL;
pub type FnInstallELAMCertificateInfo = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnInterlockedFlushSList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnInterlockedPopEntrySList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnInterlockedPushEntrySList =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY) -> PSLIST_ENTRY;
pub type FnInterlockedPushListSListEx =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, ULONG) -> PSLIST_ENTRY;
pub type FnIsBadCodePtr = unsafe extern "system" fn(FARPROC) -> BOOL;
pub type FnIsBadHugeReadPtr = unsafe extern "system" fn(*const VOID, UINT_PTR) -> BOOL;
pub type FnIsBadHugeWritePtr = unsafe extern "system" fn(LPVOID, UINT_PTR) -> BOOL;
pub type FnIsBadReadPtr = unsafe extern "system" fn(*const VOID, UINT_PTR) -> BOOL;
pub type FnIsBadStringPtrA = unsafe extern "system" fn(LPCSTR, UINT_PTR) -> BOOL;
pub type FnIsBadStringPtrW = unsafe extern "system" fn(LPCWSTR, UINT_PTR) -> BOOL;
pub type FnIsBadWritePtr = unsafe extern "system" fn(LPVOID, UINT_PTR) -> BOOL;
pub type FnIsDBCSLeadByte = unsafe extern "system" fn(BYTE) -> BOOL;
pub type FnIsDBCSLeadByteEx = unsafe extern "system" fn(UINT, BYTE) -> BOOL;
pub type FnIsDebuggerPresent = unsafe extern "system" fn() -> BOOL;
pub type FnIsEnclaveTypeSupported = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnIsNLSDefinedString =
    unsafe extern "system" fn(NLS_FUNCTION, DWORD, LPNLSVERSIONINFO, LPCWSTR, INT) -> BOOL;
pub type FnIsNativeVhdBoot = unsafe extern "system" fn(PBOOL) -> BOOL;
pub type FnIsNormalizedString = unsafe extern "system" fn(NORM_FORM, LPCWSTR, c_int) -> BOOL;
pub type FnIsProcessCritical = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnIsProcessInJob = unsafe extern "system" fn(HANDLE, HANDLE, PBOOL) -> BOOL;
pub type FnIsProcessorFeaturePresent = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnIsSystemResumeAutomatic = unsafe extern "system" fn() -> BOOL;
pub type FnIsThreadAFiber = unsafe extern "system" fn() -> BOOL;
pub type FnIsThreadpoolTimerSet = unsafe extern "system" fn(PTP_TIMER) -> BOOL;
pub type FnIsValidCodePage = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnIsValidLanguageGroup = unsafe extern "system" fn(LGRPID, DWORD) -> BOOL;
pub type FnIsValidLocale = unsafe extern "system" fn(LCID, DWORD) -> BOOL;
pub type FnIsValidLocaleName = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnIsValidNLSVersion =
    unsafe extern "system" fn(NLS_FUNCTION, LPCWSTR, LPNLSVERSIONINFOEX) -> BOOL;
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
pub type FnLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
pub type FnLoadLibraryExA = unsafe extern "system" fn(LPCSTR, HANDLE, DWORD) -> HMODULE;
pub type FnLoadLibraryExW = unsafe extern "system" fn(LPCWSTR, HANDLE, DWORD) -> HMODULE;
pub type FnLoadLibraryW = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
pub type FnLoadModule = unsafe extern "system" fn(LPCSTR, LPVOID) -> DWORD;
pub type FnLoadPackagedLibrary = unsafe extern "system" fn(LPCWSTR, DWORD) -> HMODULE;
pub type FnLoadResource = unsafe extern "system" fn(HMODULE, HRSRC) -> HGLOBAL;
pub type FnLocalAlloc = unsafe extern "system" fn(UINT, SIZE_T) -> HLOCAL;
pub type FnLocalCompact = unsafe extern "system" fn(UINT) -> SIZE_T;
pub type FnLocalFileTimeToFileTime = unsafe extern "system" fn(*const FILETIME, LPFILETIME) -> BOOL;
pub type FnLocalFlags = unsafe extern "system" fn(HLOCAL) -> UINT;
pub type FnLocalFree = unsafe extern "system" fn(HLOCAL) -> HLOCAL;
pub type FnLocalHandle = unsafe extern "system" fn(LPCVOID) -> HLOCAL;
pub type FnLocalLock = unsafe extern "system" fn(HLOCAL) -> LPVOID;
pub type FnLocalReAlloc = unsafe extern "system" fn(HLOCAL, SIZE_T, UINT) -> HLOCAL;
pub type FnLocalShrink = unsafe extern "system" fn(HLOCAL, UINT) -> SIZE_T;
pub type FnLocalSize = unsafe extern "system" fn(HLOCAL) -> SIZE_T;
pub type FnLocalUnlock = unsafe extern "system" fn(HLOCAL) -> BOOL;
pub type FnLocaleNameToLCID = unsafe extern "system" fn(LPCWSTR, DWORD) -> LCID;
pub type FnLockFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD) -> BOOL;
pub type FnLockFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED) -> BOOL;
pub type FnLockResource = unsafe extern "system" fn(HGLOBAL) -> LPVOID;
pub type FnMapUserPhysicalPages = unsafe extern "system" fn(PVOID, ULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnMapUserPhysicalPagesScatter =
    unsafe extern "system" fn(*mut PVOID, ULONG_PTR, PULONG_PTR) -> BOOL;
pub type FnMapViewOfFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T) -> LPVOID;
pub type FnMapViewOfFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID) -> LPVOID;
pub type FnMapViewOfFileExNuma =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID, DWORD) -> LPVOID;
pub type FnMapViewOfFileFromApp =
    unsafe extern "system" fn(HANDLE, ULONG, ULONG64, SIZE_T) -> PVOID;
pub type FnModule32First = unsafe extern "system" fn(HANDLE, LPMODULEENTRY32) -> BOOL;
pub type FnModule32FirstW = unsafe extern "system" fn(HANDLE, LPMODULEENTRY32W) -> BOOL;
pub type FnModule32Next = unsafe extern "system" fn(HANDLE, LPMODULEENTRY32) -> BOOL;
pub type FnModule32NextW = unsafe extern "system" fn(HANDLE, LPMODULEENTRY32W) -> BOOL;
pub type FnMoveFileA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> BOOL;
pub type FnMoveFileExA = unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD) -> BOOL;
pub type FnMoveFileExW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD) -> BOOL;
pub type FnMoveFileTransactedA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD, HANDLE) -> BOOL;
pub type FnMoveFileTransactedW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD, HANDLE) -> BOOL;
pub type FnMoveFileW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> BOOL;
pub type FnMoveFileWithProgressA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD) -> BOOL;
pub type FnMoveFileWithProgressW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD) -> BOOL;
pub type FnMulDiv = unsafe extern "system" fn(c_int, c_int, c_int) -> c_int;
pub type FnMultiByteToWideChar =
    unsafe extern "system" fn(UINT, DWORD, LPCSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnNeedCurrentDirectoryForExePathA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnNeedCurrentDirectoryForExePathW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnNormalizeString =
    unsafe extern "system" fn(NORM_FORM, LPCWSTR, c_int, LPWSTR, c_int) -> c_int;
pub type FnNotifyUILanguageChange =
    unsafe extern "system" fn(DWORD, PCWSTR, PCWSTR, DWORD, PDWORD) -> BOOL;
pub type FnOfferVirtualMemory = unsafe extern "system" fn(PVOID, SIZE_T, OFFER_PRIORITY) -> DWORD;
pub type FnOpenEventA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenEventW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenFile = unsafe extern "system" fn(LPCSTR, LPOFSTRUCT, UINT) -> HFILE;
pub type FnOpenFileById = unsafe extern "system" fn(
    HANDLE,
    LPFILE_ID_DESCRIPTOR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
) -> HANDLE;
pub type FnOpenFileMappingA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenFileMappingW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenJobObjectA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenJobObjectW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenMutexA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenMutexW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenPrivateNamespaceA = unsafe extern "system" fn(LPVOID, LPCSTR) -> HANDLE;
pub type FnOpenPrivateNamespaceW = unsafe extern "system" fn(LPVOID, LPCWSTR) -> HANDLE;
pub type FnOpenProcess = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
pub type FnOpenProcessToken = unsafe extern "system" fn(HANDLE, DWORD, PHANDLE) -> BOOL;
pub type FnOpenSemaphoreA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenSemaphoreW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOpenThread = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
pub type FnOpenThreadToken = unsafe extern "system" fn(HANDLE, DWORD, BOOL, PHANDLE) -> BOOL;
pub type FnOpenWaitableTimerA = unsafe extern "system" fn(DWORD, BOOL, LPCSTR) -> HANDLE;
pub type FnOpenWaitableTimerW = unsafe extern "system" fn(DWORD, BOOL, LPCWSTR) -> HANDLE;
pub type FnOutputDebugStringA = unsafe extern "system" fn(LPCSTR) -> ();
pub type FnOutputDebugStringW = unsafe extern "system" fn(LPCWSTR) -> ();
pub type FnPeekConsoleInputA =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnPeekConsoleInputW =
    unsafe extern "system" fn(HANDLE, PINPUT_RECORD, DWORD, LPDWORD) -> BOOL;
pub type FnPeekNamedPipe =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnPostQueuedCompletionStatus =
    unsafe extern "system" fn(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED) -> BOOL;
pub type FnPowerClearRequest = unsafe extern "system" fn(HANDLE, POWER_REQUEST_TYPE) -> BOOL;
pub type FnPowerCreateRequest = unsafe extern "system" fn(PREASON_CONTEXT) -> HANDLE;
pub type FnPowerSetRequest = unsafe extern "system" fn(HANDLE, POWER_REQUEST_TYPE) -> BOOL;
pub type FnPrefetchVirtualMemory =
    unsafe extern "system" fn(HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG) -> BOOL;
pub type FnPrepareTape = unsafe extern "system" fn(HANDLE, DWORD, BOOL) -> DWORD;
pub type FnProcess32First = unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32) -> BOOL;
pub type FnProcess32FirstW = unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32W) -> BOOL;
pub type FnProcess32Next = unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32) -> BOOL;
pub type FnProcess32NextW = unsafe extern "system" fn(HANDLE, LPPROCESSENTRY32W) -> BOOL;
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
pub type FnQueryDosDeviceA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> DWORD;
pub type FnQueryDosDeviceW = unsafe extern "system" fn(LPCWSTR, LPWSTR, DWORD) -> DWORD;
pub type FnQueryFullProcessImageNameA =
    unsafe extern "system" fn(HANDLE, DWORD, LPSTR, PDWORD) -> BOOL;
pub type FnQueryFullProcessImageNameW =
    unsafe extern "system" fn(HANDLE, DWORD, LPWSTR, PDWORD) -> BOOL;
pub type FnQueryIdleProcessorCycleTime = unsafe extern "system" fn(PULONG, PULONG64) -> BOOL;
pub type FnQueryIdleProcessorCycleTimeEx =
    unsafe extern "system" fn(USHORT, PULONG, PULONG64) -> BOOL;
pub type FnQueryInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD, LPDWORD) -> BOOL;
pub type FnQueryIoRateControlInformationJobObject =
    unsafe extern "system" fn(HANDLE, PCWSTR, *mut ULONG) -> DWORD;
pub type FnQueryMemoryResourceNotification = unsafe extern "system" fn(HANDLE, PBOOL) -> BOOL;
pub type FnQueryPerformanceCounter = unsafe extern "system" fn(*mut LARGE_INTEGER) -> BOOL;
pub type FnQueryPerformanceFrequency = unsafe extern "system" fn(*mut LARGE_INTEGER) -> BOOL;
pub type FnQueryProcessAffinityUpdateMode = unsafe extern "system" fn(HANDLE, LPDWORD) -> BOOL;
pub type FnQueryProcessCycleTime = unsafe extern "system" fn(HANDLE, PULONG64) -> BOOL;
pub type FnQueryProtectedPolicy = unsafe extern "system" fn(LPCGUID, PULONG_PTR) -> BOOL;
pub type FnQueryThreadCycleTime = unsafe extern "system" fn(HANDLE, PULONG64) -> BOOL;
pub type FnQueryThreadProfiling = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> DWORD;
pub type FnQueryThreadpoolStackInformation =
    unsafe extern "system" fn(PTP_POOL, PTP_POOL_STACK_INFORMATION) -> BOOL;
pub type FnQueryUmsThreadInformation =
    unsafe extern "system" fn(PUMS_CONTEXT, UMS_THREAD_INFO_CLASS, PVOID, ULONG, PULONG) -> BOOL;
pub type FnQueryUnbiasedInterruptTime = unsafe extern "system" fn(PULONGLONG) -> BOOL;
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
pub type FnReadThreadProfilingData =
    unsafe extern "system" fn(HANDLE, DWORD, PPERFORMANCE_DATA) -> DWORD;
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
pub type FnRegSetValueExA =
    unsafe extern "system" fn(HKEY, LPCSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegSetValueExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegUnLoadKeyA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegUnLoadKeyW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegisterApplicationRecoveryCallback =
    unsafe extern "system" fn(APPLICATION_RECOVERY_CALLBACK, PVOID, DWORD, DWORD) -> HRESULT;
pub type FnRegisterApplicationRestart = unsafe extern "system" fn(PCWSTR, DWORD) -> HRESULT;
pub type FnRegisterBadMemoryNotification =
    unsafe extern "system" fn(PBAD_MEMORY_CALLBACK_ROUTINE) -> PVOID;
pub type FnRegisterWaitForSingleObject =
    unsafe extern "system" fn(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG) -> BOOL;
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
pub type FnRemoveDirectoryTransactedA = unsafe extern "system" fn(LPCSTR, HANDLE) -> BOOL;
pub type FnRemoveDirectoryTransactedW = unsafe extern "system" fn(LPCWSTR, HANDLE) -> BOOL;
pub type FnRemoveDirectoryW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnRemoveDllDirectory = unsafe extern "system" fn(DLL_DIRECTORY_COOKIE) -> BOOL;
pub type FnRemoveSecureMemoryCacheCallback =
    unsafe extern "system" fn(PSECURE_MEMORY_CACHE_CALLBACK) -> BOOL;
pub type FnRemoveVectoredContinueHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnRemoveVectoredExceptionHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnReplaceFileA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID) -> ();
pub type FnReplaceFileW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID) -> ();
pub type FnReplacePartitionUnit = unsafe extern "system" fn(PWSTR, PWSTR, ULONG) -> BOOL;
pub type FnRequestDeviceWakeup = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnRequestWakeupLatency = unsafe extern "system" fn(LATENCY_TIME) -> BOOL;
pub type FnResetEvent = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnResetWriteWatch = unsafe extern "system" fn(LPVOID, SIZE_T) -> UINT;
pub type FnResizePseudoConsole = unsafe extern "system" fn(HPCON, COORD) -> HRESULT;
pub type FnResolveLocaleName = unsafe extern "system" fn(LPCWSTR, LPWSTR, c_int) -> c_int;
pub type FnRestoreLastError = unsafe extern "system" fn(DWORD) -> ();
pub type FnResumeThread = unsafe extern "system" fn(HANDLE) -> DWORD;
pub type FnRtlAddFunctionTable =
    unsafe extern "system" fn(PRUNTIME_FUNCTION, DWORD, DWORD64) -> BOOLEAN;
pub type FnRtlCaptureContext = unsafe extern "system" fn(PCONTEXT) -> ();
pub type FnRtlCaptureStackBackTrace =
    unsafe extern "system" fn(DWORD, DWORD, *mut PVOID, PDWORD) -> WORD;
pub type FnRtlCompareMemory = unsafe extern "system" fn(*const VOID, *const VOID, SIZE_T) -> SIZE_T;
pub type FnRtlCopyMemory = unsafe extern "system" fn(*mut c_void, *const c_void, usize) -> ();
pub type FnRtlDeleteFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION) -> BOOLEAN;
pub type FnRtlFillMemory = unsafe extern "system" fn(*mut c_void, usize, u8) -> ();
pub type FnRtlInstallFunctionTableCallback = unsafe extern "system" fn(
    DWORD64,
    DWORD64,
    DWORD,
    PGET_RUNTIME_FUNCTION_CALLBACK,
    PVOID,
    PCWSTR,
) -> BOOLEAN;
pub type FnRtlLookupFunctionEntry =
    unsafe extern "system" fn(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE) -> PRUNTIME_FUNCTION;
pub type FnRtlMoveMemory = unsafe extern "system" fn(*mut c_void, *const c_void, usize) -> ();
pub type FnRtlPcToFileHeader = unsafe extern "system" fn(PVOID, *mut PVOID) -> PVOID;
pub type FnRtlRestoreContext = unsafe extern "system" fn(PCONTEXT, *mut EXCEPTION_RECORD) -> ();
pub type FnRtlUnwind = unsafe extern "system" fn(PVOID, PVOID, PEXCEPTION_RECORD, PVOID) -> ();
pub type FnRtlUnwindEx = unsafe extern "system" fn(
    PVOID,
    PVOID,
    PEXCEPTION_RECORD,
    PVOID,
    PCONTEXT,
    PUNWIND_HISTORY_TABLE,
) -> ();
pub type FnRtlVirtualUnwind = unsafe extern "system" fn(
    DWORD,
    DWORD64,
    DWORD64,
    PRUNTIME_FUNCTION,
    PCONTEXT,
    *mut PVOID,
    PDWORD64,
    PKNONVOLATILE_CONTEXT_POINTERS,
) -> PEXCEPTION_ROUTINE;
pub type FnRtlZeroMemory = unsafe extern "system" fn(*mut c_void, usize) -> ();
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
pub type FnSetCachedSigningLevel = unsafe extern "system" fn(PHANDLE, ULONG, ULONG, HANDLE) -> BOOL;
pub type FnSetCalendarInfoA = unsafe extern "system" fn(LCID, CALID, CALTYPE, LPCSTR) -> BOOL;
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
pub type FnSetDefaultCommConfigA = unsafe extern "system" fn(LPCSTR, LPCOMMCONFIG, DWORD) -> BOOL;
pub type FnSetDefaultCommConfigW = unsafe extern "system" fn(LPCWSTR, LPCOMMCONFIG, DWORD) -> BOOL;
pub type FnSetDefaultDllDirectories = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnSetDllDirectoryA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnSetDllDirectoryW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnSetDynamicTimeZoneInformation =
    unsafe extern "system" fn(*const DYNAMIC_TIME_ZONE_INFORMATION) -> BOOL;
pub type FnSetEndOfFile = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnSetEnvironmentStringsA = unsafe extern "system" fn(LPCH) -> BOOL;
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
pub type FnSetFileAttributesTransactedA = unsafe extern "system" fn(LPCSTR, DWORD, HANDLE) -> BOOL;
pub type FnSetFileAttributesTransactedW = unsafe extern "system" fn(LPCWSTR, DWORD, HANDLE) -> BOOL;
pub type FnSetFileAttributesW = unsafe extern "system" fn(LPCWSTR, DWORD) -> BOOL;
pub type FnSetFileBandwidthReservation =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, BOOL, LPDWORD, LPDWORD) -> BOOL;
pub type FnSetFileCompletionNotificationModes = unsafe extern "system" fn(HANDLE, UCHAR) -> BOOL;
pub type FnSetFileInformationByHandle =
    unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetFileIoOverlappedRange = unsafe extern "system" fn(HANDLE, PUCHAR, ULONG) -> BOOL;
pub type FnSetFilePointer = unsafe extern "system" fn(HANDLE, LONG, PLONG, DWORD) -> DWORD;
pub type FnSetFilePointerEx =
    unsafe extern "system" fn(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) -> BOOL;
pub type FnSetFileShortNameA = unsafe extern "system" fn(HANDLE, LPCSTR) -> BOOL;
pub type FnSetFileShortNameW = unsafe extern "system" fn(HANDLE, LPCWSTR) -> BOOL;
pub type FnSetFileTime =
    unsafe extern "system" fn(HANDLE, *const FILETIME, *const FILETIME, *const FILETIME) -> BOOL;
pub type FnSetFileValidData = unsafe extern "system" fn(HANDLE, LONGLONG) -> BOOL;
pub type FnSetFirmwareEnvironmentVariableA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, PVOID, DWORD) -> BOOL;
pub type FnSetFirmwareEnvironmentVariableExA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, PVOID, DWORD, DWORD) -> BOOL;
pub type FnSetFirmwareEnvironmentVariableExW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, PVOID, DWORD, DWORD) -> BOOL;
pub type FnSetFirmwareEnvironmentVariableW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, PVOID, DWORD) -> BOOL;
pub type FnSetHandleCount = unsafe extern "system" fn(UINT) -> UINT;
pub type FnSetHandleInformation = unsafe extern "system" fn(HANDLE, DWORD, DWORD) -> BOOL;
pub type FnSetInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetIoRateControlInformationJobObject =
    unsafe extern "system" fn(HANDLE, *mut JOBOBJECT_IO_RATE_CONTROL_INFORMATION) -> DWORD;
pub type FnSetLastError = unsafe extern "system" fn(DWORD) -> ();
pub type FnSetLocalTime = unsafe extern "system" fn(*const SYSTEMTIME) -> BOOL;
pub type FnSetLocaleInfoA = unsafe extern "system" fn(LCID, LCTYPE, LPCSTR) -> BOOL;
pub type FnSetLocaleInfoW = unsafe extern "system" fn(LCID, LCTYPE, LPCWSTR) -> BOOL;
pub type FnSetMailslotInfo = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetMessageWaitingIndicator = unsafe extern "system" fn(HANDLE, ULONG) -> BOOL;
pub type FnSetNamedPipeHandleState =
    unsafe extern "system" fn(HANDLE, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnSetPriorityClass = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetProcessAffinityMask = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetProcessAffinityUpdateMode = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnSetProcessDEPPolicy = unsafe extern "system" fn(DWORD) -> BOOL;
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
pub type FnSetSearchPathMode = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnSetStdHandle = unsafe extern "system" fn(DWORD, HANDLE) -> BOOL;
pub type FnSetStdHandleEx = unsafe extern "system" fn(DWORD, HANDLE, PHANDLE) -> BOOL;
pub type FnSetSystemFileCacheSize = unsafe extern "system" fn(SIZE_T, SIZE_T, DWORD) -> BOOL;
pub type FnSetSystemPowerState = unsafe extern "system" fn(BOOL, BOOL) -> BOOL;
pub type FnSetSystemTime = unsafe extern "system" fn(*const SYSTEMTIME) -> BOOL;
pub type FnSetSystemTimeAdjustment = unsafe extern "system" fn(DWORD, BOOL) -> BOOL;
pub type FnSetTapeParameters = unsafe extern "system" fn(HANDLE, DWORD, LPVOID) -> DWORD;
pub type FnSetTapePosition =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD, BOOL) -> DWORD;
pub type FnSetThreadAffinityMask = unsafe extern "system" fn(HANDLE, DWORD_PTR) -> DWORD_PTR;
pub type FnSetThreadContext = unsafe extern "system" fn(HANDLE, *const CONTEXT) -> BOOL;
pub type FnSetThreadErrorMode = unsafe extern "system" fn(DWORD, LPDWORD) -> BOOL;
pub type FnSetThreadExecutionState = unsafe extern "system" fn(EXECUTION_STATE) -> EXECUTION_STATE;
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
pub type FnSetTimerQueueTimer =
    unsafe extern "system" fn(HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, BOOL) -> HANDLE;
pub type FnSetUmsThreadInformation =
    unsafe extern "system" fn(PUMS_CONTEXT, UMS_THREAD_INFO_CLASS, PVOID, ULONG) -> BOOL;
pub type FnSetUnhandledExceptionFilter =
    unsafe extern "system" fn(LPTOP_LEVEL_EXCEPTION_FILTER) -> LPTOP_LEVEL_EXCEPTION_FILTER;
pub type FnSetUserGeoID = unsafe extern "system" fn(GEOID) -> BOOL;
pub type FnSetVolumeLabelA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> BOOL;
pub type FnSetVolumeLabelW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> BOOL;
pub type FnSetVolumeMountPointA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> BOOL;
pub type FnSetVolumeMountPointW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> BOOL;
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
pub type FnTerminateJobObject = unsafe extern "system" fn(HANDLE, UINT) -> BOOL;
pub type FnTerminateProcess = unsafe extern "system" fn(HANDLE, UINT) -> BOOL;
pub type FnTerminateThread = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
pub type FnThread32First = unsafe extern "system" fn(HANDLE, LPTHREADENTRY32) -> BOOL;
pub type FnThread32Next = unsafe extern "system" fn(HANDLE, LPTHREADENTRY32) -> BOOL;
pub type FnTlsAlloc = unsafe extern "system" fn() -> DWORD;
pub type FnTlsFree = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnTlsGetValue = unsafe extern "system" fn(DWORD) -> LPVOID;
pub type FnTlsSetValue = unsafe extern "system" fn(DWORD, LPVOID) -> BOOL;
pub type FnToolhelp32ReadProcessMemory =
    unsafe extern "system" fn(DWORD, LPCVOID, LPVOID, SIZE_T, *mut SIZE_T) -> BOOL;
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
pub type FnUmsThreadYield = unsafe extern "system" fn(PVOID) -> BOOL;
pub type FnUnhandledExceptionFilter = unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG;
pub type FnUnlockFile = unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, DWORD) -> BOOL;
pub type FnUnlockFileEx =
    unsafe extern "system" fn(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED) -> BOOL;
pub type FnUnmapViewOfFile = unsafe extern "system" fn(LPCVOID) -> BOOL;
pub type FnUnmapViewOfFileEx = unsafe extern "system" fn(PVOID, ULONG) -> BOOL;
pub type FnUnregisterApplicationRecoveryCallback = unsafe extern "system" fn() -> HRESULT;
pub type FnUnregisterApplicationRestart = unsafe extern "system" fn() -> HRESULT;
pub type FnUnregisterBadMemoryNotification = unsafe extern "system" fn(PVOID) -> BOOL;
pub type FnUnregisterWait = unsafe extern "system" fn(HANDLE) -> BOOL;
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
pub type FnUpdateResourceA =
    unsafe extern "system" fn(HANDLE, LPCSTR, LPCSTR, WORD, LPVOID, DWORD) -> BOOL;
pub type FnUpdateResourceW =
    unsafe extern "system" fn(HANDLE, LPCWSTR, LPCWSTR, WORD, LPVOID, DWORD) -> BOOL;
pub type FnVerLanguageNameA = unsafe extern "system" fn(DWORD, LPSTR, DWORD) -> DWORD;
pub type FnVerLanguageNameW = unsafe extern "system" fn(DWORD, LPWSTR, DWORD) -> DWORD;
pub type FnVerSetConditionMask = unsafe extern "system" fn(ULONGLONG, DWORD, BYTE) -> ULONGLONG;
pub type FnVerifyScripts = unsafe extern "system" fn(DWORD, LPCWSTR, c_int, LPCWSTR, c_int) -> BOOL;
pub type FnVerifyVersionInfoA =
    unsafe extern "system" fn(LPOSVERSIONINFOEXA, DWORD, DWORDLONG) -> BOOL;
pub type FnVerifyVersionInfoW =
    unsafe extern "system" fn(LPOSVERSIONINFOEXW, DWORD, DWORDLONG) -> BOOL;
pub type FnVirtualAlloc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
pub type FnVirtualAllocEx =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
pub type FnVirtualAllocExNuma =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD) -> LPVOID;
pub type FnVirtualFree = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD) -> BOOL;
pub type FnVirtualFreeEx = unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD) -> BOOL;
pub type FnVirtualLock = unsafe extern "system" fn(LPVOID, SIZE_T) -> BOOL;
pub type FnVirtualProtect = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, PDWORD) -> BOOL;
pub type FnVirtualProtectEx =
    unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) -> BOOL;
pub type FnVirtualQuery =
    unsafe extern "system" fn(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T;
pub type FnVirtualQueryEx =
    unsafe extern "system" fn(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) -> SIZE_T;
pub type FnVirtualUnlock = unsafe extern "system" fn(LPVOID, SIZE_T) -> BOOL;
pub type FnWTSGetActiveConsoleSessionId = unsafe extern "system" fn() -> DWORD;
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
pub type FnWaitNamedPipeA = unsafe extern "system" fn(LPCSTR, DWORD) -> BOOL;
pub type FnWaitNamedPipeW = unsafe extern "system" fn(LPCWSTR, DWORD) -> BOOL;
pub type FnWakeAllConditionVariable = unsafe extern "system" fn(PCONDITION_VARIABLE) -> ();
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
pub type FnWinExec = unsafe extern "system" fn(LPCSTR, UINT) -> UINT;
pub type FnWow64DisableWow64FsRedirection = unsafe extern "system" fn(*mut PVOID) -> BOOL;
pub type FnWow64EnableWow64FsRedirection = unsafe extern "system" fn(BOOLEAN) -> BOOLEAN;
pub type FnWow64GetThreadContext = unsafe extern "system" fn(HANDLE, PWOW64_CONTEXT) -> BOOL;
pub type FnWow64GetThreadSelectorEntry =
    unsafe extern "system" fn(HANDLE, DWORD, PWOW64_LDT_ENTRY) -> BOOL;
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
pub type FnWritePrivateProfileSectionA = unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR) -> BOOL;
pub type FnWritePrivateProfileSectionW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR) -> BOOL;
pub type FnWritePrivateProfileStringA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, LPCSTR) -> BOOL;
pub type FnWritePrivateProfileStringW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR) -> BOOL;
pub type FnWritePrivateProfileStructA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR) -> BOOL;
pub type FnWritePrivateProfileStructW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR) -> BOOL;
pub type FnWriteProcessMemory =
    unsafe extern "system" fn(HANDLE, LPVOID, LPCVOID, SIZE_T, *mut SIZE_T) -> BOOL;
pub type FnWriteProfileSectionA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> BOOL;
pub type FnWriteProfileSectionW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> BOOL;
pub type FnWriteProfileStringA = unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR) -> BOOL;
pub type FnWriteProfileStringW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR) -> BOOL;
pub type FnWriteTapemark = unsafe extern "system" fn(HANDLE, DWORD, DWORD, BOOL) -> DWORD;
pub type FnZombifyActCtx = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type Fn_hread = unsafe extern "system" fn(HFILE, LPVOID, c_long) -> c_long;
pub type Fn_hwrite = unsafe extern "system" fn(HFILE, LPCCH, c_long) -> c_long;
pub type Fn_lclose = unsafe extern "system" fn(HFILE) -> HFILE;
pub type Fn_lcreat = unsafe extern "system" fn(LPCSTR, c_int) -> HFILE;
pub type Fn_llseek = unsafe extern "system" fn(HFILE, LONG, c_int) -> LONG;
pub type Fn_lopen = unsafe extern "system" fn(LPCSTR, c_int) -> HFILE;
pub type Fn_lread = unsafe extern "system" fn(HFILE, LPVOID, UINT) -> UINT;
pub type Fn_lwrite = unsafe extern "system" fn(HFILE, LPCCH, UINT) -> UINT;
pub type FnlstrcatA = unsafe extern "system" fn(LPSTR, LPCSTR) -> LPSTR;
pub type FnlstrcatW = unsafe extern "system" fn(LPWSTR, LPCWSTR) -> LPWSTR;
pub type FnlstrcmpA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> c_int;
pub type FnlstrcmpW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> c_int;
pub type FnlstrcmpiA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> c_int;
pub type FnlstrcmpiW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> c_int;
pub type FnlstrcpyA = unsafe extern "system" fn(LPSTR, LPCSTR) -> LPSTR;
pub type FnlstrcpyW = unsafe extern "system" fn(LPWSTR, LPCWSTR) -> LPWSTR;
pub type FnlstrcpynA = unsafe extern "system" fn(LPSTR, LPCSTR, c_int) -> LPSTR;
pub type FnlstrcpynW = unsafe extern "system" fn(LPWSTR, LPCWSTR, c_int) -> LPWSTR;
pub type FnlstrlenA = unsafe extern "system" fn(LPCSTR) -> c_int;
pub type FnlstrlenW = unsafe extern "system" fn(LPCWSTR) -> c_int;
pub type FntimeBeginPeriod = unsafe extern "system" fn(UINT) -> MMRESULT;
pub type FntimeEndPeriod = unsafe extern "system" fn(UINT) -> MMRESULT;
pub type FntimeGetDevCaps = unsafe extern "system" fn(LPTIMECAPS, UINT) -> MMRESULT;
pub type FntimeGetTime = unsafe extern "system" fn() -> DWORD;
pub type Fnuaw_lstrcmpW = unsafe extern "system" fn(PCUWSTR, PCUWSTR) -> c_int;
pub type Fnuaw_lstrcmpiW = unsafe extern "system" fn(PCUWSTR, PCUWSTR) -> c_int;
pub type Fnuaw_lstrlenW = unsafe extern "system" fn(LPCUWSTR) -> c_int;
pub type Fnuaw_wcschr = unsafe extern "system" fn(PCUWSTR, WCHAR) -> PUWSTR;
pub type Fnuaw_wcscpy = unsafe extern "system" fn(PUWSTR, PCUWSTR) -> PUWSTR;
pub type Fnuaw_wcsicmp = unsafe extern "system" fn(PCUWSTR, PCUWSTR) -> c_int;
pub type Fnuaw_wcslen = unsafe extern "system" fn(PCUWSTR) -> size_t;
pub type Fnuaw_wcsrchr = unsafe extern "system" fn(PCUWSTR, WCHAR) -> PUWSTR;
