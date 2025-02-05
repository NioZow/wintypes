use ntapi::ntapi_base::{PCLIENT_ID, PRTL_ATOM, RTL_ATOM};
use ntapi::ntdbg::{DEBUGOBJECTINFOCLASS, PDBGUI_WAIT_STATE_CHANGE};
use ntapi::ntexapi::{
    ATOM_INFORMATION_CLASS, EVENT_INFORMATION_CLASS, FILTER_BOOT_OPTION_OPERATION,
    MUTANT_INFORMATION_CLASS, PBOOT_ENTRY, PBOOT_OPTIONS, PCWNF_TYPE_ID, PEFI_DRIVER_ENTRY,
    PFILE_PATH, PT2_CANCEL_PARAMETERS, PT2_SET_PARAMETERS, PTIMER_APC_ROUTINE, PWNF_CHANGE_STAMP,
    PWNF_DELIVERY_DESCRIPTOR, SEMAPHORE_INFORMATION_CLASS, SHUTDOWN_ACTION, SYSDBG_COMMAND,
    SYSTEM_INFORMATION_CLASS, TIMER_INFORMATION_CLASS, TIMER_SET_INFORMATION_CLASS,
    WNF_CHANGE_STAMP, WNF_DATA_SCOPE, WNF_STATE_NAME_INFORMATION, WNF_STATE_NAME_LIFETIME,
    WORKERFACTORYINFOCLASS,
};
use ntapi::ntioapi::{
    FILE_INFORMATION_CLASS, FILE_IO_COMPLETION_INFORMATION, FS_INFORMATION_CLASS,
    IO_COMPLETION_INFORMATION_CLASS, IO_SESSION_EVENT, IO_SESSION_STATE, PFILE_BASIC_INFORMATION,
    PFILE_IO_COMPLETION_INFORMATION, PFILE_NETWORK_OPEN_INFORMATION, PIO_APC_ROUTINE,
    PIO_STATUS_BLOCK,
};
use ntapi::ntkeapi::KPROFILE_SOURCE;
use ntapi::ntldr::{
    PDELAYLOAD_FAILURE_DLL_CALLBACK, PDELAYLOAD_FAILURE_SYSTEM_ROUTINE, PLDR_DATA_TABLE_ENTRY,
    PLDR_DLL_NOTIFICATION_FUNCTION, PLDR_ENUM_CALLBACK, PLDR_ENUM_RESOURCE_ENTRY,
    PLDR_IMPORT_MODULE_CALLBACK, PLDR_RESOURCE_INFO, PLDR_VERIFY_IMAGE_INFO,
    PPS_SYSTEM_DLL_INIT_BLOCK, PRTL_PROCESS_MODULES,
};
use ntapi::ntlpcapi::{
    ALPC_HANDLE, ALPC_MESSAGE_INFORMATION_CLASS, ALPC_PORT_INFORMATION_CLASS,
    PALPC_COMPLETION_LIST_HEADER, PALPC_CONTEXT_ATTR, PALPC_DATA_VIEW_ATTR, PALPC_HANDLE,
    PALPC_MESSAGE_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, PALPC_SECURITY_ATTR, PORT_INFORMATION_CLASS,
    PPORT_MESSAGE, PPORT_VIEW, PREMOTE_PORT_VIEW,
};
use ntapi::ntpsapi::{
    MEMORY_RESERVE_TYPE, PINITIAL_TEB, PPS_APC_ROUTINE, PPS_ATTRIBUTE_LIST, PPS_CREATE_INFO,
    PROCESSINFOCLASS, PS_PROTECTION, THREADINFOCLASS,
};
use ntapi::ntseapi::PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::{
    DWORD64, KAFFINITY, LONG_PTR, PDWORD64, PSIZE_T, PULONG64, PULONG_PTR, SIZE_T, ULONG32,
    ULONG64, ULONG_PTR,
};
use winapi::shared::bcrypt::{NTSTATUS, PNTSTATUS};
use winapi::shared::evntprov::{PENABLECALLBACK, PREGHANDLE};
use winapi::shared::guiddef::{GUID, LPCGUID, LPGUID};
use winapi::shared::in6addr::IN6_ADDR;
use winapi::shared::inaddr::IN_ADDR;
use winapi::shared::ktmtypes::{NOTIFICATION_MASK, PCRM_PROTOCOL_ID, PTRANSACTION_NOTIFICATION};
use winapi::shared::minwindef::{
    BOOL, BYTE, DWORD, PBOOL, PDWORD, PUCHAR, PULONG, PUSHORT, UCHAR, ULONG, USHORT, WORD,
};
use winapi::shared::mstcpip::DL_EUI48;
use winapi::shared::ntdef::{
    BOOLEAN, CCHAR, CHAR, CLONG, EVENT_TYPE, HANDLE, LANGID, LCID, LOGICAL, LONG, LPCWSTR,
    OBJECT_ATTRIBUTES, PANSI_STRING, PBOOLEAN, PCANSI_STRING, PCCH, PCH, PCHAR, PCOEM_STRING,
    PCSTR, PCSZ, PCUNICODE_STRING, PCWCH, PCWNF_STATE_NAME, PCWSTR, PGROUP_AFFINITY, PHANDLE,
    PLARGE_INTEGER, PLCID, PLIST_ENTRY, PLONG, PLUID, PNT_PRODUCT_TYPE, POBJECT_ATTRIBUTES,
    POEM_STRING, PPROCESSOR_NUMBER, PRTL_BALANCED_NODE, PSTR, PSTRING, PULARGE_INTEGER, PULONGLONG,
    PUNICODE_STRING, PVOID, PWCH, PWCHAR, PWNF_STATE_NAME, PWSTR, STRING, TIMER_TYPE, ULONGLONG,
    VOID, WAIT_TYPE, WCHAR,
};
use winapi::um::minwinbase::{LPDEBUG_EVENT, PTHREAD_START_ROUTINE};
use winapi::um::winnt::{
    ACCESS_MASK, ACL_INFORMATION_CLASS, APC_CALLBACK_FUNCTION, AUDIT_EVENT_TYPE,
    ENLISTMENT_INFORMATION_CLASS, EXCEPTION_RECORD, EXECUTION_STATE, HEAP_INFORMATION_CLASS,
    JOBOBJECTINFOCLASS, KTMOBJECT_TYPE, OS_DEPLOYEMENT_STATE_VALUES, PACCESS_MASK, PACL,
    PCIMAGE_DELAYLOAD_DESCRIPTOR, PDEVICE_POWER_STATE, PEXCEPTION_POINTERS, PEXCEPTION_RECORD,
    PEXCEPTION_ROUTINE, PEXECUTION_STATE, PFILE_SEGMENT_ELEMENT, PFLS_CALLBACK_FUNCTION,
    PGENERIC_MAPPING, PGET_RUNTIME_FUNCTION_CALLBACK, PIMAGE_BASE_RELOCATION, PIMAGE_NT_HEADERS,
    PIMAGE_RESOURCE_DATA_ENTRY, PIMAGE_RESOURCE_DIRECTORY, PIMAGE_SECTION_HEADER,
    PIMAGE_THUNK_DATA, PJOB_SET_ARRAY, PKNONVOLATILE_CONTEXT_POINTERS, PKTMOBJECT_CURSOR,
    PLUID_AND_ATTRIBUTES, PMESSAGE_RESOURCE_ENTRY, POBJECT_TYPE_LIST, POWER_ACTION,
    POWER_INFORMATION_LEVEL, PPERFORMANCE_DATA, PPRIVILEGE_SET, PRTL_BARRIER,
    PRTL_CONDITION_VARIABLE, PRTL_CRITICAL_SECTION, PRTL_OSVERSIONINFOEXW, PRTL_OSVERSIONINFOW,
    PRTL_SRWLOCK, PRUNTIME_FUNCTION, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL,
    PSECURITY_QUALITY_OF_SERVICE, PSE_SIGNING_LEVEL, PSID, PSID_AND_ATTRIBUTES,
    PSID_AND_ATTRIBUTES_HASH, PSID_IDENTIFIER_AUTHORITY, PSLIST_ENTRY, PSLIST_HEADER,
    PTOKEN_DEFAULT_DACL, PTOKEN_GROUPS, PTOKEN_MANDATORY_POLICY, PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP, PTOKEN_PRIVILEGES, PTOKEN_SOURCE, PTOKEN_USER, PTP_CALLBACK_ENVIRON,
    PTP_CALLBACK_INSTANCE, PTP_CLEANUP_GROUP, PTP_IO, PTP_POOL, PTP_POOL_STACK_INFORMATION,
    PTP_SIMPLE_CALLBACK, PTP_TIMER, PTP_TIMER_CALLBACK, PTP_WAIT, PTP_WAIT_CALLBACK, PTP_WORK,
    PTP_WORK_CALLBACK, PUNWIND_HISTORY_TABLE, PVECTORED_EXCEPTION_HANDLER, PWOW64_CONTEXT,
    RESOURCEMANAGER_INFORMATION_CLASS, SECURITY_DESCRIPTOR_CONTROL, SECURITY_IMPERSONATION_LEVEL,
    SECURITY_INFORMATION, SE_SIGNING_LEVEL, SLIST_HEADER, SYSTEM_POWER_STATE,
    TOKEN_INFORMATION_CLASS, TOKEN_TYPE, TRANSACTIONMANAGER_INFORMATION_CLASS,
    TRANSACTION_INFORMATION_CLASS, WAITORTIMERCALLBACKFUNC, WORKERCALLBACKFUNC,
};
use winapi::vc::vadefs::va_list;
use winapi::vc::vcruntime::size_t;

use crate::types::PCONTEXT;
use ntapi::ntmisc::VDMSERVICECLASS;
use ntapi::ntmmapi::{
    MEMORY_INFORMATION_CLASS, MEMORY_PARTITION_INFORMATION_CLASS, PMEMORY_RANGE_ENTRY,
    SECTION_INFORMATION_CLASS, SECTION_INHERIT, VIRTUAL_MEMORY_INFORMATION_CLASS,
};
use ntapi::ntnls::{PCPTABLEINFO, PNLSTABLEINFO};
use ntapi::ntobapi::OBJECT_INFORMATION_CLASS;
use ntapi::ntpebteb::{PPEB, PTEB_ACTIVE_FRAME};
use ntapi::ntpnpapi::PLUGPLAY_CONTROL_CLASS;
use ntapi::ntregapi::{
    KEY_INFORMATION_CLASS, KEY_SET_INFORMATION_CLASS, KEY_VALUE_INFORMATION_CLASS, PKEY_VALUE_ENTRY,
};
use ntapi::ntrtl::{
    IMAGE_MITIGATION_POLICY, PAPPCONTAINER_SID_TYPE, PCONTEXT_EX, PGENERATE_NAME_CONTEXT,
    PPARSE_MESSAGE_CONTEXT, PPREFIX_TABLE, PPREFIX_TABLE_ENTRY, PPS_PKG_CLAIM,
    PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, PRTLP_UNHANDLED_EXCEPTION_FILTER,
    PRTL_AVL_ALLOCATE_ROUTINE, PRTL_AVL_COMPARE_ROUTINE, PRTL_AVL_FREE_ROUTINE,
    PRTL_AVL_MATCH_FUNCTION, PRTL_AVL_TABLE, PRTL_BITMAP, PRTL_BITMAP_EX, PRTL_BITMAP_RUN,
    PRTL_DEBUG_INFORMATION, PRTL_DYNAMIC_HASH_TABLE, PRTL_DYNAMIC_HASH_TABLE_CONTEXT,
    PRTL_DYNAMIC_HASH_TABLE_ENTRY, PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR, PRTL_ELEVATION_FLAGS,
    PRTL_ENUM_HEAPS_ROUTINE, PRTL_EXIT_POOL_THREAD, PRTL_GENERIC_ALLOCATE_ROUTINE,
    PRTL_GENERIC_COMPARE_ROUTINE, PRTL_GENERIC_FREE_ROUTINE, PRTL_GENERIC_TABLE, PRTL_HANDLE_TABLE,
    PRTL_HANDLE_TABLE_ENTRY, PRTL_HEAP_PARAMETERS, PRTL_HEAP_TAG_INFO, PRTL_HEAP_WALK_ENTRY,
    PRTL_QUERY_REGISTRY_TABLE, PRTL_RB_TREE, PRTL_RELATIVE_NAME_U, PRTL_RESOURCE,
    PRTL_SECURE_MEMORY_CACHE_CALLBACK, PRTL_SPLAY_LINKS, PRTL_START_POOL_THREAD,
    PRTL_TIME_ZONE_INFORMATION, PRTL_UNLOAD_EVENT_TRACE, PRTL_USER_PROCESS_INFORMATION,
    PRTL_USER_PROCESS_PARAMETERS, PTIME_FIELDS, PUSER_THREAD_START_ROUTINE, RTL_BSD_ITEM_TYPE,
    RTL_PATH_TYPE, STATE_LOCATION_TYPE, TABLE_SEARCH_RESULT,
};
use ntapi::nttp::{
    PTP_ALPC, PTP_ALPC_CALLBACK, PTP_ALPC_CALLBACK_EX, PTP_IO_CALLBACK, TP_TRACE_TYPE,
};
use ntapi::winapi_local::um::winnt::PMEM_EXTENDED_PARAMETER;

pub type FnAlpcAdjustCompletionListConcurrencyCount =
    unsafe extern "system" fn(HANDLE, ULONG) -> NTSTATUS;
pub type FnAlpcFreeCompletionListMessage = unsafe extern "system" fn(PVOID, PPORT_MESSAGE) -> ();
pub type FnAlpcGetCompletionListLastMessageInformation =
    unsafe extern "system" fn(PVOID, PULONG, PULONG) -> ();
pub type FnAlpcGetCompletionListMessageAttributes =
    unsafe extern "system" fn(PVOID, PPORT_MESSAGE) -> PALPC_MESSAGE_ATTRIBUTES;
pub type FnAlpcGetHeaderSize = unsafe extern "system" fn(ULONG) -> ULONG;
pub type FnAlpcGetMessageAttribute =
    unsafe extern "system" fn(PALPC_MESSAGE_ATTRIBUTES, ULONG) -> PVOID;
pub type FnAlpcGetMessageFromCompletionList =
    unsafe extern "system" fn(PVOID, *mut PALPC_MESSAGE_ATTRIBUTES) -> PPORT_MESSAGE;
pub type FnAlpcGetOutstandingCompletionListMessageCount = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnAlpcInitializeMessageAttribute =
    unsafe extern "system" fn(ULONG, PALPC_MESSAGE_ATTRIBUTES, ULONG, PULONG) -> NTSTATUS;
pub type FnAlpcMaxAllowedMessageLength = unsafe extern "system" fn() -> ULONG;
pub type FnAlpcRegisterCompletionList = unsafe extern "system" fn(
    HANDLE,
    PALPC_COMPLETION_LIST_HEADER,
    ULONG,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnAlpcRegisterCompletionListWorkerThread = unsafe extern "system" fn(PVOID) -> BOOLEAN;
pub type FnAlpcRundownCompletionList = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnAlpcUnregisterCompletionList = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnAlpcUnregisterCompletionListWorkerThread = unsafe extern "system" fn(PVOID) -> BOOLEAN;
pub type FnDbgBreakPoint = unsafe extern "system" fn() -> ();
pub type FnDbgPrint = unsafe extern "system" fn(PCSTR) -> ULONG;
pub type FnDbgPrintEx = unsafe extern "system" fn(ULONG, ULONG, PCSTR) -> ULONG;
pub type FnDbgPrompt = unsafe extern "system" fn(PCCH, PCH, ULONG) -> ULONG;
pub type FnDbgQueryDebugFilterState = unsafe extern "system" fn(ULONG, ULONG) -> NTSTATUS;
pub type FnDbgSetDebugFilterState = unsafe extern "system" fn(ULONG, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnDbgUiConnectToDbg = unsafe extern "system" fn() -> NTSTATUS;
pub type FnDbgUiContinue = unsafe extern "system" fn(PCLIENT_ID, NTSTATUS) -> NTSTATUS;
pub type FnDbgUiConvertStateChangeStructure =
    unsafe extern "system" fn(PDBGUI_WAIT_STATE_CHANGE, LPDEBUG_EVENT) -> NTSTATUS;
pub type FnDbgUiDebugActiveProcess = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnDbgUiGetThreadDebugObject = unsafe extern "system" fn() -> HANDLE;
pub type FnDbgUiIssueRemoteBreakin = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnDbgUiRemoteBreakin = unsafe extern "system" fn(PVOID) -> ();
pub type FnDbgUiSetThreadDebugObject = unsafe extern "system" fn(HANDLE) -> ();
pub type FnDbgUiStopDebugging = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnDbgUiWaitStateChange =
    unsafe extern "system" fn(PDBGUI_WAIT_STATE_CHANGE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnDbgUserBreakPoint = unsafe extern "system" fn() -> ();
pub type FnEtwEventRegister =
    unsafe extern "system" fn(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE) -> NTSTATUS;
pub type FnLdrAccessResource = unsafe extern "system" fn(
    PVOID,
    PIMAGE_RESOURCE_DATA_ENTRY,
    *mut PVOID,
    *mut ULONG,
) -> NTSTATUS;
pub type FnLdrAddLoadAsDataTable =
    unsafe extern "system" fn(PVOID, PWSTR, SIZE_T, HANDLE) -> NTSTATUS;
pub type FnLdrAddRefDll = unsafe extern "system" fn(ULONG, PVOID) -> NTSTATUS;
pub type FnLdrControlFlowGuardEnforced = unsafe extern "system" fn() -> BOOLEAN;
pub type FnLdrDisableThreadCalloutsForDll = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnLdrEnumResources = unsafe extern "system" fn(
    PVOID,
    PLDR_RESOURCE_INFO,
    ULONG,
    *mut ULONG,
    PLDR_ENUM_RESOURCE_ENTRY,
) -> NTSTATUS;
pub type FnLdrEnumerateLoadedModules =
    unsafe extern "system" fn(BOOLEAN, PLDR_ENUM_CALLBACK, PVOID) -> NTSTATUS;
pub type FnLdrFindEntryForAddress =
    unsafe extern "system" fn(PVOID, *mut PLDR_DATA_TABLE_ENTRY) -> NTSTATUS;
pub type FnLdrFindResourceDirectory_U = unsafe extern "system" fn(
    PVOID,
    PLDR_RESOURCE_INFO,
    ULONG,
    *mut PIMAGE_RESOURCE_DIRECTORY,
) -> NTSTATUS;
pub type FnLdrFindResource_U = unsafe extern "system" fn(
    PVOID,
    PLDR_RESOURCE_INFO,
    ULONG,
    *mut PIMAGE_RESOURCE_DATA_ENTRY,
) -> NTSTATUS;
pub type FnLdrGetDllDirectory = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnLdrGetDllFullName = unsafe extern "system" fn(PVOID, PUNICODE_STRING) -> NTSTATUS;
pub type FnLdrGetDllHandle =
    unsafe extern "system" fn(PWSTR, PULONG, PUNICODE_STRING, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetDllHandleByMapping = unsafe extern "system" fn(PVOID, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetDllHandleByName =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetDllHandleEx =
    unsafe extern "system" fn(ULONG, PWSTR, PULONG, PUNICODE_STRING, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetFileNameFromLoadAsDataTable =
    unsafe extern "system" fn(PVOID, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetKnownDllSectionHandle =
    unsafe extern "system" fn(PCWSTR, BOOLEAN, PHANDLE) -> NTSTATUS;
pub type FnLdrGetProcedureAddress =
    unsafe extern "system" fn(PVOID, PANSI_STRING, ULONG, *mut PVOID) -> NTSTATUS;
pub type FnLdrGetProcedureAddressEx =
    unsafe extern "system" fn(PVOID, PANSI_STRING, ULONG, *mut PVOID, ULONG) -> NTSTATUS;
pub type FnLdrGetProcedureAddressForCaller = unsafe extern "system" fn(
    PVOID,
    PANSI_STRING,
    ULONG,
    *mut PVOID,
    ULONG,
    *mut PVOID,
) -> NTSTATUS;
pub type FnLdrInitializeThunk = unsafe extern "system" fn(PCONTEXT, PVOID) -> ();
pub type FnLdrLoadDll =
    unsafe extern "system" fn(PWSTR, PULONG, PUNICODE_STRING, *mut PVOID) -> NTSTATUS;
pub type FnLdrLockLoaderLock = unsafe extern "system" fn(ULONG, *mut ULONG, *mut PVOID) -> NTSTATUS;
pub type FnLdrOpenImageFileOptionsKey =
    unsafe extern "system" fn(PUNICODE_STRING, BOOLEAN, PHANDLE) -> NTSTATUS;
pub type FnLdrProcessRelocationBlock =
    unsafe extern "system" fn(ULONG_PTR, ULONG, PUSHORT, LONG_PTR) -> PIMAGE_BASE_RELOCATION;
pub type FnLdrQueryImageFileExecutionOptions =
    unsafe extern "system" fn(PUNICODE_STRING, PCWSTR, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnLdrQueryImageFileExecutionOptionsEx = unsafe extern "system" fn(
    PUNICODE_STRING,
    PCWSTR,
    ULONG,
    PVOID,
    ULONG,
    PULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnLdrQueryImageFileKeyOption =
    unsafe extern "system" fn(HANDLE, PCWSTR, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnLdrQueryModuleServiceTags = unsafe extern "system" fn(PVOID, PULONG, PULONG) -> NTSTATUS;
pub type FnLdrQueryProcessModuleInformation =
    unsafe extern "system" fn(PRTL_PROCESS_MODULES, ULONG, PULONG) -> NTSTATUS;
pub type FnLdrRegisterDllNotification =
    unsafe extern "system" fn(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, *mut PVOID) -> NTSTATUS;
pub type FnLdrRemoveLoadAsDataTable =
    unsafe extern "system" fn(PVOID, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnLdrResolveDelayLoadedAPI = unsafe extern "system" fn(
    PVOID,
    PCIMAGE_DELAYLOAD_DESCRIPTOR,
    PDELAYLOAD_FAILURE_DLL_CALLBACK,
    PDELAYLOAD_FAILURE_SYSTEM_ROUTINE,
    PIMAGE_THUNK_DATA,
    ULONG,
) -> PVOID;
pub type FnLdrResolveDelayLoadsFromDll = unsafe extern "system" fn(PVOID, PCSTR, ULONG) -> NTSTATUS;
pub type FnLdrSetDefaultDllDirectories = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnLdrSetDllDirectory = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnLdrSetImplicitPathOptions = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnLdrShutdownProcess = unsafe extern "system" fn() -> NTSTATUS;
pub type FnLdrShutdownThread = unsafe extern "system" fn() -> NTSTATUS;
pub type FnLdrSystemDllInitBlock = unsafe extern "system" fn() -> PPS_SYSTEM_DLL_INIT_BLOCK;
pub type FnLdrUnloadDll = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnLdrUnlockLoaderLock = unsafe extern "system" fn(ULONG, PVOID) -> NTSTATUS;
pub type FnLdrUnregisterDllNotification = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnLdrVerifyImageMatchesChecksum =
    unsafe extern "system" fn(HANDLE, PLDR_IMPORT_MODULE_CALLBACK, PVOID, PUSHORT) -> NTSTATUS;
pub type FnLdrVerifyImageMatchesChecksumEx =
    unsafe extern "system" fn(HANDLE, PLDR_VERIFY_IMAGE_INFO) -> NTSTATUS;
pub type FnNtAcceptConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PVOID,
    PPORT_MESSAGE,
    BOOLEAN,
    PPORT_VIEW,
    PREMOTE_PORT_VIEW,
) -> NTSTATUS;
pub type FnNtAccessCheck = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    HANDLE,
    ACCESS_MASK,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnNtAccessCheckAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    ACCESS_MASK,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtAccessCheckByType = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    ACCESS_MASK,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnNtAccessCheckByTypeAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    PSID,
    ACCESS_MASK,
    AUDIT_EVENT_TYPE,
    ULONG,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtAccessCheckByTypeResultList = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    ACCESS_MASK,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnNtAccessCheckByTypeResultListAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    PSID,
    ACCESS_MASK,
    AUDIT_EVENT_TYPE,
    ULONG,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtAccessCheckByTypeResultListAndAuditAlarmByHandle =
    unsafe extern "system" fn(
        PUNICODE_STRING,
        PVOID,
        HANDLE,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PSECURITY_DESCRIPTOR,
        PSID,
        ACCESS_MASK,
        AUDIT_EVENT_TYPE,
        ULONG,
        POBJECT_TYPE_LIST,
        ULONG,
        PGENERIC_MAPPING,
        BOOLEAN,
        PACCESS_MASK,
        PNTSTATUS,
        PBOOLEAN,
    ) -> NTSTATUS;
pub type FnNtAddAtom = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM) -> NTSTATUS;
pub type FnNtAddAtomEx = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM, ULONG) -> NTSTATUS;
pub type FnNtAddBootEntry = unsafe extern "system" fn(PBOOT_ENTRY, PULONG) -> NTSTATUS;
pub type FnNtAddDriverEntry = unsafe extern "system" fn(PEFI_DRIVER_ENTRY, PULONG) -> NTSTATUS;
pub type FnNtAdjustGroupsToken = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    PTOKEN_GROUPS,
    ULONG,
    PTOKEN_GROUPS,
    PULONG,
) -> NTSTATUS;
pub type FnNtAdjustPrivilegesToken = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    PTOKEN_PRIVILEGES,
    ULONG,
    PTOKEN_PRIVILEGES,
    PULONG,
) -> NTSTATUS;
pub type FnNtAdjustTokenClaimsAndDeviceGroups = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    BOOLEAN,
    BOOLEAN,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    ULONG,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    ULONG,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    ULONG,
    PTOKEN_GROUPS,
    PULONG,
    PULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtAlertResumeThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnNtAlertThread = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtAlertThreadByThreadId = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtAllocateLocallyUniqueId = unsafe extern "system" fn(PLUID) -> NTSTATUS;
pub type FnNtAllocateReserveObject =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, MEMORY_RESERVE_TYPE) -> NTSTATUS;
pub type FnNtAllocateUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnNtAllocateUuids =
    unsafe extern "system" fn(PULARGE_INTEGER, PULONG, PULONG, PCHAR) -> NTSTATUS;
pub type FnNtAllocateVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG) -> NTSTATUS;
pub type FnNtAlpcAcceptConnectPort = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    PVOID,
    PPORT_MESSAGE,
    PALPC_MESSAGE_ATTRIBUTES,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtAlpcCancelMessage =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_CONTEXT_ATTR) -> NTSTATUS;
pub type FnNtAlpcConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    ULONG,
    PSID,
    PPORT_MESSAGE,
    PULONG,
    PALPC_MESSAGE_ATTRIBUTES,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtAlpcConnectPortEx = unsafe extern "system" fn(
    PHANDLE,
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    ULONG,
    PSECURITY_DESCRIPTOR,
    PPORT_MESSAGE,
    PSIZE_T,
    PALPC_MESSAGE_ATTRIBUTES,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtAlpcCreatePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtAlpcCreatePortSection =
    unsafe extern "system" fn(HANDLE, ULONG, HANDLE, SIZE_T, PALPC_HANDLE, PSIZE_T) -> NTSTATUS;
pub type FnNtAlpcCreateResourceReserve =
    unsafe extern "system" fn(HANDLE, ULONG, SIZE_T, PALPC_HANDLE) -> NTSTATUS;
pub type FnNtAlpcCreateSectionView =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_DATA_VIEW_ATTR) -> NTSTATUS;
pub type FnNtAlpcCreateSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_SECURITY_ATTR) -> NTSTATUS;
pub type FnNtAlpcDeletePortSection =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnNtAlpcDeleteResourceReserve =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnNtAlpcDeleteSectionView = unsafe extern "system" fn(HANDLE, ULONG, PVOID) -> NTSTATUS;
pub type FnNtAlpcDeleteSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnNtAlpcDisconnectPort = unsafe extern "system" fn(HANDLE, ULONG) -> NTSTATUS;
pub type FnNtAlpcImpersonateClientContainerOfPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG) -> NTSTATUS;
pub type FnNtAlpcImpersonateClientOfPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, PVOID) -> NTSTATUS;
pub type FnNtAlpcOpenSenderProcess = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PPORT_MESSAGE,
    ULONG,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
) -> NTSTATUS;
pub type FnNtAlpcOpenSenderThread = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PPORT_MESSAGE,
    ULONG,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
) -> NTSTATUS;
pub type FnNtAlpcQueryInformation = unsafe extern "system" fn(
    HANDLE,
    ALPC_PORT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtAlpcQueryInformationMessage = unsafe extern "system" fn(
    HANDLE,
    PPORT_MESSAGE,
    ALPC_MESSAGE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtAlpcRevokeSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnNtAlpcSendWaitReceivePort = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PPORT_MESSAGE,
    PALPC_MESSAGE_ATTRIBUTES,
    PPORT_MESSAGE,
    PSIZE_T,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtAlpcSetInformation =
    unsafe extern "system" fn(HANDLE, ALPC_PORT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtAreMappedFilesTheSame = unsafe extern "system" fn(PVOID, PVOID) -> NTSTATUS;
pub type FnNtAssignProcessToJobObject = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtAssociateWaitCompletionPacket = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    HANDLE,
    PVOID,
    PVOID,
    NTSTATUS,
    ULONG_PTR,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtCallbackReturn = unsafe extern "system" fn(PVOID, ULONG, NTSTATUS) -> NTSTATUS;
pub type FnNtCancelIoFile = unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnNtCancelIoFileEx =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnNtCancelSynchronousIoFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnNtCancelTimer = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnNtCancelTimer2 = unsafe extern "system" fn(HANDLE, PT2_CANCEL_PARAMETERS) -> NTSTATUS;
pub type FnNtCancelWaitCompletionPacket = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnNtClearEvent = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtCloseObjectAuditAlarm =
    unsafe extern "system" fn(PUNICODE_STRING, PVOID, BOOLEAN) -> NTSTATUS;
pub type FnNtCommitComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtCommitEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtCommitTransaction = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnNtCompactKeys = unsafe extern "system" fn(ULONG, *mut HANDLE) -> NTSTATUS;
pub type FnNtCompareObjects = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtCompareTokens = unsafe extern "system" fn(HANDLE, HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnNtCompleteConnectPort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtCompressKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    PSECURITY_QUALITY_OF_SERVICE,
    PPORT_VIEW,
    PREMOTE_PORT_VIEW,
    PULONG,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnNtContinue = unsafe extern "system" fn(PCONTEXT, BOOLEAN) -> NTSTATUS;
pub type FnNtCreateDebugObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtCreateDirectoryObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtCreateDirectoryObjectEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG) -> NTSTATUS;
pub type FnNtCreateEnlistment = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    HANDLE,
    HANDLE,
    POBJECT_ATTRIBUTES,
    ULONG,
    NOTIFICATION_MASK,
    PVOID,
) -> NTSTATUS;
pub type FnNtCreateEvent = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    EVENT_TYPE,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtCreateEventPair =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtCreateFile = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtCreateIRTimer = unsafe extern "system" fn(PHANDLE, ACCESS_MASK) -> NTSTATUS;
pub type FnNtCreateIoCompletion =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtCreateJobObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtCreateJobSet = unsafe extern "system" fn(ULONG, PJOB_SET_ARRAY, ULONG) -> NTSTATUS;
pub type FnNtCreateKey = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtCreateKeyTransacted = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    HANDLE,
    PULONG,
) -> NTSTATUS;
pub type FnNtCreateKeyedEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtCreateLowBoxToken = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PSID,
    ULONG,
    PSID_AND_ATTRIBUTES,
    ULONG,
    *mut HANDLE,
) -> NTSTATUS;
pub type FnNtCreateMailslotFile = unsafe extern "system" fn(
    PHANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtCreateMutant =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN) -> NTSTATUS;
pub type FnNtCreateNamedPipeFile = unsafe extern "system" fn(
    PHANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtCreatePagingFile =
    unsafe extern "system" fn(PUNICODE_STRING, PLARGE_INTEGER, PLARGE_INTEGER, ULONG) -> NTSTATUS;
pub type FnNtCreatePartition =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtCreatePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnNtCreatePrivateNamespace =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID) -> NTSTATUS;
pub type FnNtCreateProcess = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    BOOLEAN,
    HANDLE,
    HANDLE,
    HANDLE,
) -> NTSTATUS;
pub type FnNtCreateProcessEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    ULONG,
    HANDLE,
    HANDLE,
    HANDLE,
    ULONG,
) -> NTSTATUS;
pub type FnNtCreateProfile = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PVOID,
    SIZE_T,
    ULONG,
    PULONG,
    ULONG,
    KPROFILE_SOURCE,
    KAFFINITY,
) -> NTSTATUS;
pub type FnNtCreateProfileEx = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PVOID,
    SIZE_T,
    ULONG,
    PULONG,
    ULONG,
    KPROFILE_SOURCE,
    USHORT,
    PGROUP_AFFINITY,
) -> NTSTATUS;
pub type FnNtCreateResourceManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    HANDLE,
    LPGUID,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnNtCreateSection = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE,
) -> NTSTATUS;
pub type FnNtCreateSectionEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE,
    PMEM_EXTENDED_PARAMETER,
    ULONG,
) -> NTSTATUS;
pub type FnNtCreateSemaphore =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG) -> NTSTATUS;
pub type FnNtCreateSymbolicLinkObject = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnNtCreateThread = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PCLIENT_ID,
    PCONTEXT,
    PINITIAL_TEB,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtCreateThreadEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;
pub type FnNtCreateTimer =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE) -> NTSTATUS;
pub type FnNtCreateTimer2 =
    unsafe extern "system" fn(PHANDLE, PVOID, PVOID, ULONG, ACCESS_MASK) -> NTSTATUS;
pub type FnNtCreateToken = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    TOKEN_TYPE,
    PLUID,
    PLARGE_INTEGER,
    PTOKEN_USER,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL,
    PTOKEN_SOURCE,
) -> NTSTATUS;
pub type FnNtCreateTokenEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    TOKEN_TYPE,
    PLUID,
    PLARGE_INTEGER,
    PTOKEN_USER,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    PTOKEN_MANDATORY_POLICY,
    PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL,
    PTOKEN_SOURCE,
) -> NTSTATUS;
pub type FnNtCreateTransaction = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    LPGUID,
    HANDLE,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnNtCreateTransactionManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnNtCreateUserProcess = unsafe extern "system" fn(
    PHANDLE,
    PHANDLE,
    ACCESS_MASK,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    ULONG,
    ULONG,
    PVOID,
    PPS_CREATE_INFO,
    PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;
pub type FnNtCreateWaitCompletionPacket =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtCreateWaitablePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnNtCreateWnfStateName = unsafe extern "system" fn(
    PWNF_STATE_NAME,
    WNF_STATE_NAME_LIFETIME,
    WNF_DATA_SCOPE,
    BOOLEAN,
    PCWNF_TYPE_ID,
    ULONG,
    PSECURITY_DESCRIPTOR,
) -> NTSTATUS;
pub type FnNtCreateWorkerFactory = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
) -> NTSTATUS;
pub type FnNtDebugActiveProcess = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtDebugContinue = unsafe extern "system" fn(HANDLE, PCLIENT_ID, NTSTATUS) -> NTSTATUS;
pub type FnNtDelayExecution = unsafe extern "system" fn(BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtDeleteAtom = unsafe extern "system" fn(RTL_ATOM) -> NTSTATUS;
pub type FnNtDeleteBootEntry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnNtDeleteDriverEntry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnNtDeleteFile = unsafe extern "system" fn(POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtDeleteKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtDeleteObjectAuditAlarm =
    unsafe extern "system" fn(PUNICODE_STRING, PVOID, BOOLEAN) -> NTSTATUS;
pub type FnNtDeletePrivateNamespace = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtDeleteValueKey = unsafe extern "system" fn(HANDLE, PUNICODE_STRING) -> NTSTATUS;
pub type FnNtDeleteWnfStateData =
    unsafe extern "system" fn(PCWNF_STATE_NAME, *const VOID) -> NTSTATUS;
pub type FnNtDeleteWnfStateName = unsafe extern "system" fn(PCWNF_STATE_NAME) -> NTSTATUS;
pub type FnNtDeviceIoControlFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtDisableLastKnownGood = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtDisplayString = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnNtDrawText = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnNtDuplicateObject = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    HANDLE,
    PHANDLE,
    ACCESS_MASK,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnNtDuplicateToken = unsafe extern "system" fn(
    HANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    BOOLEAN,
    TOKEN_TYPE,
    PHANDLE,
) -> NTSTATUS;
pub type FnNtEnableLastKnownGood = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtEnumerateBootEntries = unsafe extern "system" fn(PVOID, PULONG) -> NTSTATUS;
pub type FnNtEnumerateDriverEntries = unsafe extern "system" fn(PVOID, PULONG) -> NTSTATUS;
pub type FnNtEnumerateKey = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    KEY_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtEnumerateSystemEnvironmentValuesEx =
    unsafe extern "system" fn(ULONG, PVOID, PULONG) -> NTSTATUS;
pub type FnNtEnumerateTransactionObject =
    unsafe extern "system" fn(HANDLE, KTMOBJECT_TYPE, PKTMOBJECT_CURSOR, ULONG, PULONG) -> NTSTATUS;
pub type FnNtEnumerateValueKey = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    KEY_VALUE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtExtendSection = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtFilterBootOption =
    unsafe extern "system" fn(FILTER_BOOT_OPTION_OPERATION, ULONG, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnNtFilterToken = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_GROUPS,
    PHANDLE,
) -> NTSTATUS;
pub type FnNtFilterTokenEx = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_GROUPS,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    PUNICODE_STRING,
    PTOKEN_GROUPS,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    PHANDLE,
) -> NTSTATUS;
pub type FnNtFindAtom = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM) -> NTSTATUS;
pub type FnNtFlushBuffersFile = unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnNtFlushBuffersFileEx =
    unsafe extern "system" fn(HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnNtFlushInstallUILanguage = unsafe extern "system" fn(LANGID, ULONG) -> NTSTATUS;
pub type FnNtFlushInstructionCache = unsafe extern "system" fn(HANDLE, PVOID, SIZE_T) -> NTSTATUS;
pub type FnNtFlushKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtFlushProcessWriteBuffers = unsafe extern "system" fn() -> ();
pub type FnNtFlushWriteBuffer = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtFreeUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnNtFreeVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnNtFreezeRegistry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnNtFreezeTransactions =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtFsControlFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtGetCachedSigningLevel = unsafe extern "system" fn(
    HANDLE,
    PULONG,
    PSE_SIGNING_LEVEL,
    PUCHAR,
    PULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtGetCompleteWnfStateSubscription = unsafe extern "system" fn(
    PWNF_STATE_NAME,
    *mut ULONG64,
    ULONG,
    ULONG,
    PWNF_DELIVERY_DESCRIPTOR,
    ULONG,
) -> NTSTATUS;
pub type FnNtGetContextThread = unsafe extern "system" fn(HANDLE, PCONTEXT) -> NTSTATUS;
pub type FnNtGetCurrentProcessorNumber = unsafe extern "system" fn() -> ULONG;
pub type FnNtGetDevicePowerState =
    unsafe extern "system" fn(HANDLE, PDEVICE_POWER_STATE) -> NTSTATUS;
pub type FnNtGetMUIRegistryInfo = unsafe extern "system" fn(ULONG, PULONG, PVOID) -> NTSTATUS;
pub type FnNtGetNextProcess =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE) -> NTSTATUS;
pub type FnNtGetNextThread =
    unsafe extern "system" fn(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE) -> NTSTATUS;
pub type FnNtGetNlsSectionPtr =
    unsafe extern "system" fn(ULONG, ULONG, PVOID, *mut PVOID, PULONG) -> NTSTATUS;
pub type FnNtGetNotificationResourceManager = unsafe extern "system" fn(
    HANDLE,
    PTRANSACTION_NOTIFICATION,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
    ULONG,
    ULONG_PTR,
) -> NTSTATUS;
pub type FnNtGetTickCount = unsafe extern "system" fn() -> ULONG;
pub type FnNtGetWriteWatch = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PVOID,
    SIZE_T,
    *mut PVOID,
    PULONG_PTR,
    PULONG,
) -> NTSTATUS;
pub type FnNtImpersonateAnonymousToken = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtImpersonateClientOfPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtImpersonateThread =
    unsafe extern "system" fn(HANDLE, HANDLE, PSECURITY_QUALITY_OF_SERVICE) -> NTSTATUS;
pub type FnNtInitializeNlsFiles =
    unsafe extern "system" fn(*mut PVOID, PLCID, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtInitializeRegistry = unsafe extern "system" fn(USHORT) -> NTSTATUS;
pub type FnNtInitiatePowerAction =
    unsafe extern "system" fn(POWER_ACTION, SYSTEM_POWER_STATE, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnNtIsProcessInJob = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtIsSystemResumeAutomatic = unsafe extern "system" fn() -> BOOLEAN;
pub type FnNtIsUILanguageComitted = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtListenPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtLoadDriver = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnNtLoadKey =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtLoadKey2 =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtLoadKeyEx = unsafe extern "system" fn(
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    ULONG,
    HANDLE,
    HANDLE,
    ACCESS_MASK,
    PHANDLE,
    PIO_STATUS_BLOCK,
) -> NTSTATUS;
pub type FnNtLockFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    ULONG,
    BOOLEAN,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtLockProductActivationKeys =
    unsafe extern "system" fn(*mut ULONG, *mut ULONG) -> NTSTATUS;
pub type FnNtLockRegistryKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtLockVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnNtMakePermanentObject = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtMakeTemporaryObject = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtManagePartition =
    unsafe extern "system" fn(MEMORY_PARTITION_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtMapCMFModule =
    unsafe extern "system" fn(ULONG, ULONG, PULONG, PULONG, PULONG, *mut PVOID) -> NTSTATUS;
pub type FnNtMapUserPhysicalPages =
    unsafe extern "system" fn(PVOID, ULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnNtMapUserPhysicalPagesScatter =
    unsafe extern "system" fn(*mut PVOID, ULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnNtMapViewOfSection = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut PVOID,
    ULONG_PTR,
    SIZE_T,
    PLARGE_INTEGER,
    PSIZE_T,
    SECTION_INHERIT,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnNtModifyBootEntry = unsafe extern "system" fn(PBOOT_ENTRY) -> NTSTATUS;
pub type FnNtModifyDriverEntry = unsafe extern "system" fn(PEFI_DRIVER_ENTRY) -> NTSTATUS;
pub type FnNtNotifyChangeDirectoryFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtNotifyChangeKey = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtNotifyChangeMultipleKeys = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    *mut OBJECT_ATTRIBUTES,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtNotifyChangeSession = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PLARGE_INTEGER,
    IO_SESSION_EVENT,
    IO_SESSION_STATE,
    IO_SESSION_STATE,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtOpenDirectoryObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenEnlistment =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenEventPair =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenFile = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnNtOpenIoCompletion =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenJobObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenKey =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenKeyEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtOpenKeyTransacted =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE) -> NTSTATUS;
pub type FnNtOpenKeyTransactedEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE) -> NTSTATUS;
pub type FnNtOpenKeyedEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenMutant =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenObjectAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    ACCESS_MASK,
    ACCESS_MASK,
    PPRIVILEGE_SET,
    BOOLEAN,
    BOOLEAN,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtOpenPartition =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenPrivateNamespace =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID) -> NTSTATUS;
pub type FnNtOpenProcess =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) -> NTSTATUS;
pub type FnNtOpenProcessToken = unsafe extern "system" fn(HANDLE, ACCESS_MASK, PHANDLE) -> NTSTATUS;
pub type FnNtOpenProcessTokenEx =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, ULONG, PHANDLE) -> NTSTATUS;
pub type FnNtOpenResourceManager =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenSection =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenSemaphore =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenSession =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenSymbolicLinkObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenThread =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) -> NTSTATUS;
pub type FnNtOpenThreadToken =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE) -> NTSTATUS;
pub type FnNtOpenThreadTokenEx =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE) -> NTSTATUS;
pub type FnNtOpenTimer =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtOpenTransaction =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE) -> NTSTATUS;
pub type FnNtOpenTransactionManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
    LPGUID,
    ULONG,
) -> NTSTATUS;
pub type FnNtPlugPlayControl =
    unsafe extern "system" fn(PLUGPLAY_CONTROL_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtPowerInformation =
    unsafe extern "system" fn(POWER_INFORMATION_LEVEL, PVOID, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnNtPrePrepareComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtPrePrepareEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtPrepareComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtPrepareEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtPrivilegeCheck =
    unsafe extern "system" fn(HANDLE, PPRIVILEGE_SET, PBOOLEAN) -> NTSTATUS;
pub type FnNtPrivilegeObjectAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    HANDLE,
    ACCESS_MASK,
    PPRIVILEGE_SET,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtPrivilegedServiceAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PUNICODE_STRING,
    HANDLE,
    PPRIVILEGE_SET,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtPropagationComplete =
    unsafe extern "system" fn(HANDLE, ULONG, ULONG, PVOID) -> NTSTATUS;
pub type FnNtPropagationFailed = unsafe extern "system" fn(HANDLE, ULONG, NTSTATUS) -> NTSTATUS;
pub type FnNtProtectVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG, PULONG) -> NTSTATUS;
pub type FnNtPulseEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnNtQueryAttributesFile =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION) -> NTSTATUS;
pub type FnNtQueryBootEntryOrder = unsafe extern "system" fn(PULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryBootOptions = unsafe extern "system" fn(PBOOT_OPTIONS, PULONG) -> NTSTATUS;
pub type FnNtQueryDebugFilterState = unsafe extern "system" fn(ULONG, ULONG) -> NTSTATUS;
pub type FnNtQueryDefaultLocale = unsafe extern "system" fn(BOOLEAN, PLCID) -> NTSTATUS;
pub type FnNtQueryDefaultUILanguage = unsafe extern "system" fn(*mut LANGID) -> NTSTATUS;
pub type FnNtQueryDirectoryFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
    BOOLEAN,
    PUNICODE_STRING,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtQueryDirectoryObject =
    unsafe extern "system" fn(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryDriverEntryOrder = unsafe extern "system" fn(PULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryEaFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    PULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtQueryEvent =
    unsafe extern "system" fn(HANDLE, EVENT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryFullAttributesFile =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, PFILE_NETWORK_OPEN_INFORMATION) -> NTSTATUS;
pub type FnNtQueryInformationAtom =
    unsafe extern "system" fn(RTL_ATOM, ATOM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationByName = unsafe extern "system" fn(
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnNtQueryInformationEnlistment = unsafe extern "system" fn(
    HANDLE,
    ENLISTMENT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnNtQueryInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationPort =
    unsafe extern "system" fn(HANDLE, PORT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationProcess =
    unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationResourceManager = unsafe extern "system" fn(
    HANDLE,
    RESOURCEMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryInformationThread =
    unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationToken =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInformationTransaction = unsafe extern "system" fn(
    HANDLE,
    TRANSACTION_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryInformationTransactionManager = unsafe extern "system" fn(
    HANDLE,
    TRANSACTIONMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryInformationWorkerFactory =
    unsafe extern "system" fn(HANDLE, WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryInstallUILanguage = unsafe extern "system" fn(*mut LANGID) -> NTSTATUS;
pub type FnNtQueryIntervalProfile = unsafe extern "system" fn(KPROFILE_SOURCE, PULONG) -> NTSTATUS;
pub type FnNtQueryIoCompletion = unsafe extern "system" fn(
    HANDLE,
    IO_COMPLETION_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryKey =
    unsafe extern "system" fn(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryLicenseValue =
    unsafe extern "system" fn(PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryMultipleValueKey =
    unsafe extern "system" fn(HANDLE, PKEY_VALUE_ENTRY, ULONG, PVOID, PULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryMutant =
    unsafe extern "system" fn(HANDLE, MUTANT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryObject =
    unsafe extern "system" fn(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryOpenSubKeys = unsafe extern "system" fn(POBJECT_ATTRIBUTES, PULONG) -> NTSTATUS;
pub type FnNtQueryOpenSubKeysEx =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG) -> NTSTATUS;
pub type FnNtQueryPerformanceCounter =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtQueryPortInformationProcess = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtQueryQuotaInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    PSID,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtQuerySection = unsafe extern "system" fn(
    HANDLE,
    SECTION_INFORMATION_CLASS,
    PVOID,
    SIZE_T,
    PSIZE_T,
) -> NTSTATUS;
pub type FnNtQuerySecurityAttributesToken =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQuerySecurityObject = unsafe extern "system" fn(
    HANDLE,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQuerySemaphore = unsafe extern "system" fn(
    HANDLE,
    SEMAPHORE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQuerySymbolicLinkObject =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnNtQuerySystemEnvironmentValue =
    unsafe extern "system" fn(PUNICODE_STRING, PWSTR, USHORT, PUSHORT) -> NTSTATUS;
pub type FnNtQuerySystemEnvironmentValueEx =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG) -> NTSTATUS;
pub type FnNtQuerySystemInformation =
    unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQuerySystemInformationEx = unsafe extern "system" fn(
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQuerySystemTime = unsafe extern "system" fn(PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtQueryTimer =
    unsafe extern "system" fn(HANDLE, TIMER_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryTimerResolution = unsafe extern "system" fn(PULONG, PULONG, PULONG) -> NTSTATUS;
pub type FnNtQueryValueKey = unsafe extern "system" fn(
    HANDLE,
    PUNICODE_STRING,
    KEY_VALUE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    PVOID,
    MEMORY_INFORMATION_CLASS,
    PVOID,
    SIZE_T,
    PSIZE_T,
) -> NTSTATUS;
pub type FnNtQueryVolumeInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FS_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnNtQueryWnfStateData = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    PCWNF_TYPE_ID,
    *const VOID,
    PWNF_CHANGE_STAMP,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnNtQueryWnfStateNameInformation = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    WNF_STATE_NAME_INFORMATION,
    *const VOID,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtQueueApcThread =
    unsafe extern "system" fn(HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS;
pub type FnNtQueueApcThreadEx =
    unsafe extern "system" fn(HANDLE, HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS;
pub type FnNtRaiseException =
    unsafe extern "system" fn(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN) -> NTSTATUS;
pub type FnNtRaiseHardError =
    unsafe extern "system" fn(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG) -> NTSTATUS;
pub type FnNtReadFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnNtReadFileScatter = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PFILE_SEGMENT_ELEMENT,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnNtReadOnlyEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtReadRequestData =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnNtReadVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnNtRecoverEnlistment = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub type FnNtRecoverResourceManager = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtRecoverTransactionManager = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtRegisterProtocolAddressInformation =
    unsafe extern "system" fn(HANDLE, PCRM_PROTOCOL_ID, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnNtRegisterThreadTerminatePort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtReleaseKeyedEvent =
    unsafe extern "system" fn(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtReleaseMutant = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnNtReleaseSemaphore = unsafe extern "system" fn(HANDLE, LONG, PLONG) -> NTSTATUS;
pub type FnNtReleaseWorkerFactoryWorker = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtRemoveIoCompletion = unsafe extern "system" fn(
    HANDLE,
    *mut PVOID,
    *mut PVOID,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtRemoveIoCompletionEx = unsafe extern "system" fn(
    HANDLE,
    PFILE_IO_COMPLETION_INFORMATION,
    ULONG,
    PULONG,
    PLARGE_INTEGER,
    BOOLEAN,
) -> NTSTATUS;
pub type FnNtRemoveProcessDebug = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtRenameKey = unsafe extern "system" fn(HANDLE, PUNICODE_STRING) -> NTSTATUS;
pub type FnNtRenameTransactionManager =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID) -> NTSTATUS;
pub type FnNtReplaceKey =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtReplacePartitionUnit =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, ULONG) -> NTSTATUS;
pub type FnNtReplyPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtReplyWaitReceivePort =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PPORT_MESSAGE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtReplyWaitReceivePortEx = unsafe extern "system" fn(
    HANDLE,
    *mut PVOID,
    PPORT_MESSAGE,
    PPORT_MESSAGE,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnNtReplyWaitReplyPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtRequestPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtRequestWaitReplyPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnNtResetEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnNtResetWriteWatch = unsafe extern "system" fn(HANDLE, PVOID, SIZE_T) -> NTSTATUS;
pub type FnNtRestoreKey = unsafe extern "system" fn(HANDLE, HANDLE, ULONG) -> NTSTATUS;
pub type FnNtResumeProcess = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtResumeThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnNtRevertContainerImpersonation = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtRollbackComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtRollbackEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtRollbackTransaction = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnNtRollforwardTransactionManager =
    unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtSaveKey = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtSaveKeyEx = unsafe extern "system" fn(HANDLE, HANDLE, ULONG) -> NTSTATUS;
pub type FnNtSaveMergedKeys = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> NTSTATUS;
pub type FnNtSecureConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    PSECURITY_QUALITY_OF_SERVICE,
    PPORT_VIEW,
    PSID,
    PREMOTE_PORT_VIEW,
    PULONG,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnNtSerializeBoot = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtSetBootEntryOrder = unsafe extern "system" fn(PULONG, ULONG) -> NTSTATUS;
pub type FnNtSetBootOptions = unsafe extern "system" fn(PBOOT_OPTIONS, ULONG) -> NTSTATUS;
pub type FnNtSetCachedSigningLevel =
    unsafe extern "system" fn(ULONG, SE_SIGNING_LEVEL, PHANDLE, ULONG, HANDLE) -> NTSTATUS;
pub type FnNtSetContextThread = unsafe extern "system" fn(HANDLE, PCONTEXT) -> NTSTATUS;
pub type FnNtSetDebugFilterState = unsafe extern "system" fn(ULONG, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnNtSetDefaultHardErrorPort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetDefaultLocale = unsafe extern "system" fn(BOOLEAN, LCID) -> NTSTATUS;
pub type FnNtSetDefaultUILanguage = unsafe extern "system" fn(LANGID) -> NTSTATUS;
pub type FnNtSetDriverEntryOrder = unsafe extern "system" fn(PULONG, ULONG) -> NTSTATUS;
pub type FnNtSetEaFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnNtSetEventBoostPriority = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetHighWaitLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetIRTimer = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtSetInformationDebugObject =
    unsafe extern "system" fn(HANDLE, DEBUGOBJECTINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtSetInformationEnlistment =
    unsafe extern "system" fn(HANDLE, ENLISTMENT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnNtSetInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationKey =
    unsafe extern "system" fn(HANDLE, KEY_SET_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationObject =
    unsafe extern "system" fn(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationProcess =
    unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationResourceManager =
    unsafe extern "system" fn(HANDLE, RESOURCEMANAGER_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationThread =
    unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationToken =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationTransaction =
    unsafe extern "system" fn(HANDLE, TRANSACTION_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetInformationTransactionManager = unsafe extern "system" fn(
    HANDLE,
    TRANSACTIONMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtSetInformationVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    VIRTUAL_MEMORY_INFORMATION_CLASS,
    ULONG_PTR,
    PMEMORY_RANGE_ENTRY,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnNtSetInformationWorkerFactory =
    unsafe extern "system" fn(HANDLE, WORKERFACTORYINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetIntervalProfile = unsafe extern "system" fn(ULONG, KPROFILE_SOURCE) -> NTSTATUS;
pub type FnNtSetIoCompletion =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR) -> NTSTATUS;
pub type FnNtSetIoCompletionEx =
    unsafe extern "system" fn(HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR) -> NTSTATUS;
pub type FnNtSetLdtEntries =
    unsafe extern "system" fn(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnNtSetLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetLowWaitHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSetQuotaInformationFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetSecurityObject =
    unsafe extern "system" fn(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> NTSTATUS;
pub type FnNtSetSystemEnvironmentValue =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnNtSetSystemEnvironmentValueEx =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG) -> NTSTATUS;
pub type FnNtSetSystemInformation =
    unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetSystemPowerState =
    unsafe extern "system" fn(POWER_ACTION, SYSTEM_POWER_STATE, ULONG) -> NTSTATUS;
pub type FnNtSetSystemTime = unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtSetThreadExecutionState =
    unsafe extern "system" fn(EXECUTION_STATE, PEXECUTION_STATE) -> NTSTATUS;
pub type FnNtSetTimer = unsafe extern "system" fn(
    HANDLE,
    PLARGE_INTEGER,
    PTIMER_APC_ROUTINE,
    PVOID,
    BOOLEAN,
    LONG,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnNtSetTimer2 = unsafe extern "system" fn(
    HANDLE,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    PT2_SET_PARAMETERS,
) -> NTSTATUS;
pub type FnNtSetTimerEx =
    unsafe extern "system" fn(HANDLE, TIMER_SET_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetTimerResolution = unsafe extern "system" fn(ULONG, BOOLEAN, PULONG) -> NTSTATUS;
pub type FnNtSetUuidSeed = unsafe extern "system" fn(PCHAR) -> NTSTATUS;
pub type FnNtSetValueKey =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnNtSetVolumeInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FS_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnNtSetWnfProcessNotificationEvent = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtShutdownSystem = unsafe extern "system" fn(SHUTDOWN_ACTION) -> NTSTATUS;
pub type FnNtShutdownWorkerFactory = unsafe extern "system" fn(HANDLE, *mut LONG) -> NTSTATUS;
pub type FnNtSignalAndWaitForSingleObject =
    unsafe extern "system" fn(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtSinglePhaseReject = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtStartProfile = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtStopProfile = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSubscribeWnfStateChange =
    unsafe extern "system" fn(PCWNF_STATE_NAME, WNF_CHANGE_STAMP, ULONG, PULONG64) -> NTSTATUS;
pub type FnNtSuspendProcess = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtSuspendThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnNtSystemDebugControl =
    unsafe extern "system" fn(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtTerminateJobObject = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnNtTerminateProcess = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnNtTerminateThread = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnNtTestAlert = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtThawRegistry = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtThawTransactions = unsafe extern "system" fn() -> NTSTATUS;
pub type FnNtTraceControl =
    unsafe extern "system" fn(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnNtTraceEvent = unsafe extern "system" fn(HANDLE, ULONG, ULONG, PVOID) -> NTSTATUS;
pub type FnNtTranslateFilePath =
    unsafe extern "system" fn(PFILE_PATH, ULONG, PFILE_PATH, PULONG) -> NTSTATUS;
pub type FnNtUmsThreadYield = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnNtUnloadDriver = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnNtUnloadKey = unsafe extern "system" fn(POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnNtUnloadKey2 = unsafe extern "system" fn(POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnNtUnloadKeyEx = unsafe extern "system" fn(POBJECT_ATTRIBUTES, HANDLE) -> NTSTATUS;
pub type FnNtUnlockFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    ULONG,
) -> NTSTATUS;
pub type FnNtUnlockVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnNtUnmapViewOfSection = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub type FnNtUnmapViewOfSectionEx = unsafe extern "system" fn(HANDLE, PVOID, ULONG) -> NTSTATUS;
pub type FnNtUnsubscribeWnfStateChange = unsafe extern "system" fn(PCWNF_STATE_NAME) -> NTSTATUS;
pub type FnNtUpdateWnfStateData = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    *const VOID,
    ULONG,
    PCWNF_TYPE_ID,
    *const VOID,
    WNF_CHANGE_STAMP,
    LOGICAL,
) -> NTSTATUS;
pub type FnNtVdmControl = unsafe extern "system" fn(VDMSERVICECLASS, PVOID) -> NTSTATUS;
pub type FnNtWaitForAlertByThreadId = unsafe extern "system" fn(PVOID, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtWaitForDebugEvent =
    unsafe extern "system" fn(HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID) -> NTSTATUS;
pub type FnNtWaitForKeyedEvent =
    unsafe extern "system" fn(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtWaitForMultipleObjects =
    unsafe extern "system" fn(ULONG, *mut HANDLE, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtWaitForMultipleObjects32 =
    unsafe extern "system" fn(ULONG, *mut LONG, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtWaitForSingleObject =
    unsafe extern "system" fn(HANDLE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnNtWaitForWorkViaWorkerFactory =
    unsafe extern "system" fn(HANDLE, *mut FILE_IO_COMPLETION_INFORMATION) -> NTSTATUS;
pub type FnNtWaitHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtWaitLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtWorkerFactoryWorkerReady = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnNtWriteFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnNtWriteFileGather = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PFILE_SEGMENT_ELEMENT,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnNtWriteRequestData =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnNtWriteVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnNtYieldExecution = unsafe extern "system" fn() -> NTSTATUS;
pub type FnPfxFindPrefix = unsafe extern "system" fn(PPREFIX_TABLE, PSTRING) -> PPREFIX_TABLE_ENTRY;
pub type FnPfxInitialize = unsafe extern "system" fn(PPREFIX_TABLE) -> ();
pub type FnPfxInsertPrefix =
    unsafe extern "system" fn(PPREFIX_TABLE, PSTRING, PPREFIX_TABLE_ENTRY) -> BOOLEAN;
pub type FnPfxRemovePrefix = unsafe extern "system" fn(PPREFIX_TABLE, PPREFIX_TABLE_ENTRY) -> ();
pub type FnRtlAbsoluteToSelfRelativeSD =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG) -> NTSTATUS;
pub type FnRtlAcquirePebLock = unsafe extern "system" fn() -> ();
pub type FnRtlAcquirePrivilege =
    unsafe extern "system" fn(PULONG, ULONG, ULONG, *mut PVOID) -> NTSTATUS;
pub type FnRtlAcquireReleaseSRWLockExclusive = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlAcquireResourceExclusive =
    unsafe extern "system" fn(PRTL_RESOURCE, BOOLEAN) -> BOOLEAN;
pub type FnRtlAcquireResourceShared = unsafe extern "system" fn(PRTL_RESOURCE, BOOLEAN) -> BOOLEAN;
pub type FnRtlAcquireSRWLockExclusive = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlAcquireSRWLockShared = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlAddAccessAllowedAce =
    unsafe extern "system" fn(PACL, ULONG, ACCESS_MASK, PSID) -> NTSTATUS;
pub type FnRtlAddAccessAllowedAceEx =
    unsafe extern "system" fn(PACL, ULONG, ULONG, ACCESS_MASK, PSID) -> NTSTATUS;
pub type FnRtlAddAccessAllowedObjectAce = unsafe extern "system" fn(
    PACL,
    ULONG,
    ULONG,
    ACCESS_MASK,
    *mut GUID,
    *mut GUID,
    PSID,
) -> NTSTATUS;
pub type FnRtlAddAccessDeniedAce =
    unsafe extern "system" fn(PACL, ULONG, ACCESS_MASK, PSID) -> NTSTATUS;
pub type FnRtlAddAccessDeniedAceEx =
    unsafe extern "system" fn(PACL, ULONG, ULONG, ACCESS_MASK, PSID) -> NTSTATUS;
pub type FnRtlAddAccessDeniedObjectAce = unsafe extern "system" fn(
    PACL,
    ULONG,
    ULONG,
    ACCESS_MASK,
    *mut GUID,
    *mut GUID,
    PSID,
) -> NTSTATUS;
pub type FnRtlAddAce = unsafe extern "system" fn(PACL, ULONG, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnRtlAddAtomToAtomTable = unsafe extern "system" fn(PVOID, PWSTR, PRTL_ATOM) -> NTSTATUS;
pub type FnRtlAddAuditAccessAce =
    unsafe extern "system" fn(PACL, ULONG, ACCESS_MASK, PSID, BOOLEAN, BOOLEAN) -> NTSTATUS;
pub type FnRtlAddAuditAccessAceEx =
    unsafe extern "system" fn(PACL, ULONG, ULONG, ACCESS_MASK, PSID, BOOLEAN, BOOLEAN) -> NTSTATUS;
pub type FnRtlAddAuditAccessObjectAce = unsafe extern "system" fn(
    PACL,
    ULONG,
    ULONG,
    ACCESS_MASK,
    *mut GUID,
    *mut GUID,
    PSID,
    BOOLEAN,
    BOOLEAN,
) -> NTSTATUS;
pub type FnRtlAddCompoundAce =
    unsafe extern "system" fn(PACL, ULONG, UCHAR, ACCESS_MASK, PSID, PSID) -> NTSTATUS;
pub type FnRtlAddFunctionTable =
    unsafe extern "system" fn(PRUNTIME_FUNCTION, DWORD, DWORD64) -> BOOLEAN;
pub type FnRtlAddGrowableFunctionTable = unsafe extern "system" fn(
    *mut PVOID,
    PRUNTIME_FUNCTION,
    DWORD,
    DWORD,
    ULONG_PTR,
    ULONG_PTR,
) -> DWORD;
pub type FnRtlAddIntegrityLabelToBoundaryDescriptor =
    unsafe extern "system" fn(*mut PVOID, PSID) -> NTSTATUS;
pub type FnRtlAddMandatoryAce =
    unsafe extern "system" fn(PACL, ULONG, ULONG, PSID, UCHAR, ACCESS_MASK) -> NTSTATUS;
pub type FnRtlAddSIDToBoundaryDescriptor = unsafe extern "system" fn(*mut PVOID, PSID) -> NTSTATUS;
pub type FnRtlAddVectoredContinueHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnRtlAddVectoredExceptionHandler =
    unsafe extern "system" fn(ULONG, PVECTORED_EXCEPTION_HANDLER) -> PVOID;
pub type FnRtlAddressInSectionTable =
    unsafe extern "system" fn(PIMAGE_NT_HEADERS, PVOID, ULONG) -> PVOID;
pub type FnRtlAdjustPrivilege =
    unsafe extern "system" fn(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN) -> NTSTATUS;
pub type FnRtlAllocateAndInitializeSid = unsafe extern "system" fn(
    PSID_IDENTIFIER_AUTHORITY,
    UCHAR,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    *mut PSID,
) -> NTSTATUS;
pub type FnRtlAllocateHandle =
    unsafe extern "system" fn(PRTL_HANDLE_TABLE, PULONG) -> PRTL_HANDLE_TABLE_ENTRY;
pub type FnRtlAllocateHeap = unsafe extern "system" fn(PVOID, ULONG, SIZE_T) -> PVOID;
pub type FnRtlAllocateMemoryBlockLookaside =
    unsafe extern "system" fn(PVOID, ULONG, *mut PVOID) -> NTSTATUS;
pub type FnRtlAllocateMemoryZone = unsafe extern "system" fn(PVOID, SIZE_T, *mut PVOID) -> NTSTATUS;
pub type FnRtlAnsiCharToUnicodeChar = unsafe extern "system" fn(*mut PUCHAR) -> WCHAR;
pub type FnRtlAnsiStringToUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PCANSI_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlAppendAsciizToString = unsafe extern "system" fn(PSTRING, PSTR) -> NTSTATUS;
pub type FnRtlAppendStringToString = unsafe extern "system" fn(PSTRING, *const STRING) -> NTSTATUS;
pub type FnRtlAppendUnicodeStringToString =
    unsafe extern "system" fn(PUNICODE_STRING, PCUNICODE_STRING) -> NTSTATUS;
pub type FnRtlAppendUnicodeToString =
    unsafe extern "system" fn(PUNICODE_STRING, PCWSTR) -> NTSTATUS;
pub type FnRtlAppxIsFileOwnedByTrustedInstaller =
    unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnRtlAreAllAccessesGranted =
    unsafe extern "system" fn(ACCESS_MASK, ACCESS_MASK) -> BOOLEAN;
pub type FnRtlAreAnyAccessesGranted =
    unsafe extern "system" fn(ACCESS_MASK, ACCESS_MASK) -> BOOLEAN;
pub type FnRtlAreBitsClear = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> BOOLEAN;
pub type FnRtlAreBitsSet = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> BOOLEAN;
pub type FnRtlAreLongPathsEnabled = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlAssert = unsafe extern "system" fn(PVOID, PVOID, ULONG, PSTR) -> ();
pub type FnRtlBarrier = unsafe extern "system" fn(PRTL_BARRIER, ULONG) -> BOOLEAN;
pub type FnRtlBarrierForDelete = unsafe extern "system" fn(PRTL_BARRIER, ULONG) -> BOOLEAN;
pub type FnRtlCapabilityCheck =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCaptureContext = unsafe extern "system" fn(PCONTEXT) -> ();
pub type FnRtlCaptureStackBackTrace =
    unsafe extern "system" fn(DWORD, DWORD, *mut PVOID, PDWORD) -> WORD;
pub type FnRtlCharToInteger = unsafe extern "system" fn(PCSZ, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlCheckBootStatusIntegrity = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCheckForOrphanedCriticalSections = unsafe extern "system" fn(HANDLE) -> ();
pub type FnRtlCheckPortableOperatingSystem = unsafe extern "system" fn(PBOOLEAN) -> NTSTATUS;
pub type FnRtlCheckRegistryKey = unsafe extern "system" fn(ULONG, PWSTR) -> NTSTATUS;
pub type FnRtlCheckSandboxedToken = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCheckTokenCapability = unsafe extern "system" fn(HANDLE, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCheckTokenMembership = unsafe extern "system" fn(HANDLE, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCheckTokenMembershipEx =
    unsafe extern "system" fn(HANDLE, PSID, ULONG, PBOOLEAN) -> NTSTATUS;
pub type FnRtlCleanUpTEBLangLists = unsafe extern "system" fn() -> ();
pub type FnRtlClearAllBits = unsafe extern "system" fn(PRTL_BITMAP) -> ();
pub type FnRtlClearAllBitsEx = unsafe extern "system" fn(PRTL_BITMAP_EX) -> ();
pub type FnRtlClearBit = unsafe extern "system" fn(PRTL_BITMAP, ULONG) -> ();
pub type FnRtlClearBitEx = unsafe extern "system" fn(PRTL_BITMAP_EX, ULONG64) -> ();
pub type FnRtlClearBits = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ();
pub type FnRtlCloneUserProcess = unsafe extern "system" fn(
    ULONG,
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    PRTL_USER_PROCESS_INFORMATION,
) -> NTSTATUS;
pub type FnRtlCommitDebugInfo = unsafe extern "system" fn(PRTL_DEBUG_INFORMATION, SIZE_T) -> PVOID;
pub type FnRtlCompactHeap = unsafe extern "system" fn(PVOID, ULONG) -> SIZE_T;
pub type FnRtlCompareAltitudes =
    unsafe extern "system" fn(PCUNICODE_STRING, PCUNICODE_STRING) -> LONG;
pub type FnRtlCompareMemory = unsafe extern "system" fn(*const VOID, *const VOID, SIZE_T) -> SIZE_T;
pub type FnRtlCompareMemoryUlong = unsafe extern "system" fn(PVOID, SIZE_T, ULONG) -> SIZE_T;
pub type FnRtlCompareString =
    unsafe extern "system" fn(*const STRING, *const STRING, BOOLEAN) -> LONG;
pub type FnRtlCompareUnicodeString =
    unsafe extern "system" fn(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> LONG;
pub type FnRtlCompareUnicodeStrings =
    unsafe extern "system" fn(PCWCH, SIZE_T, PCWCH, SIZE_T, BOOLEAN) -> LONG;
pub type FnRtlCompressBuffer = unsafe extern "system" fn(
    USHORT,
    PUCHAR,
    ULONG,
    PUCHAR,
    ULONG,
    ULONG,
    PULONG,
    PVOID,
) -> NTSTATUS;
pub type FnRtlComputeCrc32 = unsafe extern "system" fn(ULONG32, PVOID, ULONG) -> ULONG32;
pub type FnRtlComputeImportTableHash = unsafe extern "system" fn(HANDLE, PCHAR, ULONG) -> NTSTATUS;
pub type FnRtlComputePrivatizedDllName_U =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlConnectToSm =
    unsafe extern "system" fn(PUNICODE_STRING, HANDLE, DWORD, PHANDLE) -> NTSTATUS;
pub type FnRtlConsoleMultiByteToUnicodeN =
    unsafe extern "system" fn(PWCH, ULONG, PULONG, PCH, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlContractHashTable = unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE) -> BOOLEAN;
pub type FnRtlConvertDeviceFamilyInfoToString =
    unsafe extern "system" fn(PDWORD, PDWORD, PWSTR, PWSTR) -> DWORD;
pub type FnRtlConvertExclusiveToShared = unsafe extern "system" fn(PRTL_RESOURCE) -> ();
pub type FnRtlConvertLCIDToString =
    unsafe extern "system" fn(LCID, ULONG, ULONG, PWSTR, ULONG) -> NTSTATUS;
pub type FnRtlConvertSharedToExclusive = unsafe extern "system" fn(PRTL_RESOURCE) -> ();
pub type FnRtlConvertSidToUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PSID, BOOLEAN) -> NTSTATUS;
pub type FnRtlConvertToAutoInheritSecurityObject = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    *mut GUID,
    BOOLEAN,
    PGENERIC_MAPPING,
) -> NTSTATUS;
pub type FnRtlCopyBitMap = unsafe extern "system" fn(PRTL_BITMAP, PRTL_BITMAP, ULONG) -> ();
pub type FnRtlCopyExtendedContext =
    unsafe extern "system" fn(PCONTEXT_EX, ULONG, PCONTEXT_EX) -> ULONG;
pub type FnRtlCopyLuid = unsafe extern "system" fn(PLUID, PLUID) -> ();
pub type FnRtlCopyLuidAndAttributesArray =
    unsafe extern "system" fn(ULONG, PLUID_AND_ATTRIBUTES, PLUID_AND_ATTRIBUTES) -> ();
pub type FnRtlCopyMemory = unsafe extern "system" fn(*mut c_void, *const c_void, usize) -> ();
pub type FnRtlCopySecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, *mut PSECURITY_DESCRIPTOR) -> NTSTATUS;
pub type FnRtlCopySid = unsafe extern "system" fn(ULONG, PSID, PSID) -> NTSTATUS;
pub type FnRtlCopySidAndAttributesArray = unsafe extern "system" fn(
    ULONG,
    PSID_AND_ATTRIBUTES,
    ULONG,
    PSID_AND_ATTRIBUTES,
    PSID,
    *mut PSID,
    PULONG,
) -> NTSTATUS;
pub type FnRtlCopyString = unsafe extern "system" fn(PSTRING, *const STRING) -> ();
pub type FnRtlCopyUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PCUNICODE_STRING) -> ();
pub type FnRtlCrc32 = unsafe extern "system" fn(*const c_void, size_t, DWORD) -> DWORD;
pub type FnRtlCrc64 = unsafe extern "system" fn(*const c_void, size_t, ULONGLONG) -> ULONGLONG;
pub type FnRtlCreateAcl = unsafe extern "system" fn(PACL, ULONG, ULONG) -> NTSTATUS;
pub type FnRtlCreateAtomTable = unsafe extern "system" fn(ULONG, *mut PVOID) -> NTSTATUS;
pub type FnRtlCreateBootStatusDataFile = unsafe extern "system" fn() -> NTSTATUS;
pub type FnRtlCreateBoundaryDescriptor = unsafe extern "system" fn(PUNICODE_STRING, ULONG) -> PVOID;
pub type FnRtlCreateEnvironment = unsafe extern "system" fn(BOOLEAN, *mut PVOID) -> NTSTATUS;
pub type FnRtlCreateEnvironmentEx = unsafe extern "system" fn(PVOID, *mut PVOID, ULONG) -> NTSTATUS;
pub type FnRtlCreateHashTable =
    unsafe extern "system" fn(*mut PRTL_DYNAMIC_HASH_TABLE, ULONG, ULONG) -> BOOLEAN;
pub type FnRtlCreateHeap =
    unsafe extern "system" fn(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PRTL_HEAP_PARAMETERS) -> PVOID;
pub type FnRtlCreateMemoryBlockLookaside =
    unsafe extern "system" fn(*mut PVOID, ULONG, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnRtlCreateMemoryZone = unsafe extern "system" fn(*mut PVOID, SIZE_T, ULONG) -> NTSTATUS;
pub type FnRtlCreateProcessParameters = unsafe extern "system" fn(
    *mut PRTL_USER_PROCESS_PARAMETERS,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnRtlCreateProcessParametersEx = unsafe extern "system" fn(
    *mut PRTL_USER_PROCESS_PARAMETERS,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    ULONG,
) -> NTSTATUS;
pub type FnRtlCreateProcessReflection = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PVOID,
    PVOID,
    HANDLE,
    PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION,
) -> NTSTATUS;
pub type FnRtlCreateQueryDebugBuffer =
    unsafe extern "system" fn(ULONG, BOOLEAN) -> PRTL_DEBUG_INFORMATION;
pub type FnRtlCreateRegistryKey = unsafe extern "system" fn(ULONG, PWSTR) -> NTSTATUS;
pub type FnRtlCreateSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, ULONG) -> NTSTATUS;
pub type FnRtlCreateServiceSid =
    unsafe extern "system" fn(PUNICODE_STRING, PSID, PULONG) -> NTSTATUS;
pub type FnRtlCreateTagHeap = unsafe extern "system" fn(PVOID, ULONG, PWSTR, PWSTR) -> ULONG;
pub type FnRtlCreateTimer = unsafe extern "system" fn(
    HANDLE,
    PHANDLE,
    WAITORTIMERCALLBACKFUNC,
    PVOID,
    ULONG,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnRtlCreateTimerQueue = unsafe extern "system" fn(PHANDLE) -> NTSTATUS;
pub type FnRtlCreateUnicodeString = unsafe extern "system" fn(PUNICODE_STRING, PCWSTR) -> BOOLEAN;
pub type FnRtlCreateUnicodeStringFromAsciiz =
    unsafe extern "system" fn(PUNICODE_STRING, PSTR) -> BOOLEAN;
pub type FnRtlCreateUserProcess = unsafe extern "system" fn(
    PUNICODE_STRING,
    ULONG,
    PRTL_USER_PROCESS_PARAMETERS,
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    BOOLEAN,
    HANDLE,
    HANDLE,
    PRTL_USER_PROCESS_INFORMATION,
) -> NTSTATUS;
pub type FnRtlCreateUserProcessEx = unsafe extern "system" fn(
    PUNICODE_STRING,
    PRTL_USER_PROCESS_PARAMETERS,
    BOOLEAN,
    ULONG,
    PRTL_USER_PROCESS_INFORMATION,
) -> NTSTATUS;
pub type FnRtlCreateUserStack = unsafe extern "system" fn(
    SIZE_T,
    SIZE_T,
    ULONG_PTR,
    SIZE_T,
    ULONG_PTR,
    PINITIAL_TEB,
) -> NTSTATUS;
pub type FnRtlCreateUserThread = unsafe extern "system" fn(
    HANDLE,
    PSECURITY_DESCRIPTOR,
    BOOLEAN,
    ULONG,
    SIZE_T,
    SIZE_T,
    PUSER_THREAD_START_ROUTINE,
    PVOID,
    PHANDLE,
    PCLIENT_ID,
) -> NTSTATUS;
pub type FnRtlCreateVirtualAccountSid =
    unsafe extern "system" fn(PCUNICODE_STRING, ULONG, PSID, PULONG) -> NTSTATUS;
pub type FnRtlCultureNameToLCID = unsafe extern "system" fn(PUNICODE_STRING, PLCID) -> BOOLEAN;
pub type FnRtlCustomCPToUnicodeN =
    unsafe extern "system" fn(PCPTABLEINFO, PWCH, ULONG, PULONG, PCH, ULONG) -> NTSTATUS;
pub type FnRtlCutoverTimeToSystemTime =
    unsafe extern "system" fn(PTIME_FIELDS, PLARGE_INTEGER, PLARGE_INTEGER, BOOLEAN) -> BOOLEAN;
pub type FnRtlDeCommitDebugInfo =
    unsafe extern "system" fn(PRTL_DEBUG_INFORMATION, PVOID, SIZE_T) -> ();
pub type FnRtlDeNormalizeProcessParams =
    unsafe extern "system" fn(PRTL_USER_PROCESS_PARAMETERS) -> PRTL_USER_PROCESS_PARAMETERS;
pub type FnRtlDecodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnRtlDecodeRemotePointer =
    unsafe extern "system" fn(HANDLE, PVOID, *mut PVOID) -> NTSTATUS;
pub type FnRtlDecodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnRtlDecompressBuffer =
    unsafe extern "system" fn(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlDecompressBufferEx =
    unsafe extern "system" fn(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID) -> NTSTATUS;
pub type FnRtlDecompressFragment = unsafe extern "system" fn(
    USHORT,
    PUCHAR,
    ULONG,
    PUCHAR,
    ULONG,
    ULONG,
    PULONG,
    PVOID,
) -> NTSTATUS;
pub type FnRtlDefaultNpAcl = unsafe extern "system" fn(*mut PACL) -> NTSTATUS;
pub type FnRtlDelete = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlDeleteAce = unsafe extern "system" fn(PACL, ULONG) -> NTSTATUS;
pub type FnRtlDeleteAtomFromAtomTable = unsafe extern "system" fn(PVOID, RTL_ATOM) -> NTSTATUS;
pub type FnRtlDeleteBarrier = unsafe extern "system" fn(PRTL_BARRIER) -> NTSTATUS;
pub type FnRtlDeleteBoundaryDescriptor = unsafe extern "system" fn(PVOID) -> ();
pub type FnRtlDeleteCriticalSection = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> NTSTATUS;
pub type FnRtlDeleteElementGenericTable =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, PVOID) -> BOOLEAN;
pub type FnRtlDeleteElementGenericTableAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, PVOID) -> BOOLEAN;
pub type FnRtlDeleteFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION) -> BOOLEAN;
pub type FnRtlDeleteGrowableFunctionTable = unsafe extern "system" fn(PVOID) -> ();
pub type FnRtlDeleteHashTable = unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE) -> ();
pub type FnRtlDeleteNoSplay =
    unsafe extern "system" fn(PRTL_SPLAY_LINKS, *mut PRTL_SPLAY_LINKS) -> ();
pub type FnRtlDeleteRegistryValue = unsafe extern "system" fn(ULONG, PCWSTR, PCWSTR) -> NTSTATUS;
pub type FnRtlDeleteResource = unsafe extern "system" fn(PRTL_RESOURCE) -> ();
pub type FnRtlDeleteSecurityObject =
    unsafe extern "system" fn(*mut PSECURITY_DESCRIPTOR) -> NTSTATUS;
pub type FnRtlDeleteTimer = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> NTSTATUS;
pub type FnRtlDeleteTimerQueue = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnRtlDeleteTimerQueueEx = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnRtlDeregisterSecureMemoryCacheCallback =
    unsafe extern "system" fn(PRTL_SECURE_MEMORY_CACHE_CALLBACK) -> NTSTATUS;
pub type FnRtlDeregisterWait = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnRtlDeregisterWaitEx = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnRtlDeriveCapabilitySidsFromName =
    unsafe extern "system" fn(PUNICODE_STRING, PSID, PSID) -> NTSTATUS;
pub type FnRtlDestroyAtomTable = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlDestroyEnvironment = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlDestroyHandleTable = unsafe extern "system" fn(PRTL_HANDLE_TABLE) -> NTSTATUS;
pub type FnRtlDestroyHeap = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnRtlDestroyMemoryBlockLookaside = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlDestroyMemoryZone = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlDestroyProcessParameters =
    unsafe extern "system" fn(PRTL_USER_PROCESS_PARAMETERS) -> NTSTATUS;
pub type FnRtlDestroyQueryDebugBuffer =
    unsafe extern "system" fn(PRTL_DEBUG_INFORMATION) -> NTSTATUS;
pub type FnRtlDetectHeapLeaks = unsafe extern "system" fn() -> ();
pub type FnRtlDetermineDosPathNameType_U = unsafe extern "system" fn(PWSTR) -> RTL_PATH_TYPE;
pub type FnRtlDisableThreadProfiling = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlDllShutdownInProgress = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlDnsHostNameToComputerName =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlDoesFileExists_U = unsafe extern "system" fn(PWSTR) -> BOOLEAN;
pub type FnRtlDosLongPathNameToNtPathName_U_WithStatus =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> NTSTATUS;
pub type FnRtlDosLongPathNameToRelativeNtPathName_U_WithStatus =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> NTSTATUS;
pub type FnRtlDosPathNameToNtPathName_U =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> BOOLEAN;
pub type FnRtlDosPathNameToNtPathName_U_WithStatus =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> NTSTATUS;
pub type FnRtlDosPathNameToRelativeNtPathName_U =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> BOOLEAN;
pub type FnRtlDosPathNameToRelativeNtPathName_U_WithStatus =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, *mut PWSTR, PRTL_RELATIVE_NAME_U) -> NTSTATUS;
pub type FnRtlDosSearchPath_U =
    unsafe extern "system" fn(PWSTR, PWSTR, PWSTR, ULONG, PWSTR, *mut PWSTR) -> ULONG;
pub type FnRtlDosSearchPath_Ustr = unsafe extern "system" fn(
    ULONG,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    *mut PCUNICODE_STRING,
    *mut SIZE_T,
    *mut SIZE_T,
) -> NTSTATUS;
pub type FnRtlDowncaseUnicodeChar = unsafe extern "system" fn(WCHAR) -> WCHAR;
pub type FnRtlDowncaseUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlDuplicateUnicodeString =
    unsafe extern "system" fn(ULONG, PCUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlEmptyAtomTable = unsafe extern "system" fn(PVOID, BOOLEAN) -> NTSTATUS;
pub type FnRtlEnableThreadProfiling =
    unsafe extern "system" fn(HANDLE, ULONG, ULONG64, *mut PVOID) -> NTSTATUS;
pub type FnRtlEncodePointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnRtlEncodeRemotePointer =
    unsafe extern "system" fn(HANDLE, PVOID, *mut PVOID) -> NTSTATUS;
pub type FnRtlEncodeSystemPointer = unsafe extern "system" fn(PVOID) -> PVOID;
pub type FnRtlEndEnumerationHashTable =
    unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE, PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR) -> ();
pub type FnRtlEndStrongEnumerationHashTable =
    unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE, PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR) -> ();
pub type FnRtlEndWeakEnumerationHashTable =
    unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE, PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR) -> ();
pub type FnRtlEnterCriticalSection = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> NTSTATUS;
pub type FnRtlEnumProcessHeaps =
    unsafe extern "system" fn(PRTL_ENUM_HEAPS_ROUTINE, PVOID) -> NTSTATUS;
pub type FnRtlEnumerateEntryHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
) -> PRTL_DYNAMIC_HASH_TABLE_ENTRY;
pub type FnRtlEnumerateGenericTable =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, BOOLEAN) -> PVOID;
pub type FnRtlEnumerateGenericTableAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, BOOLEAN) -> PVOID;
pub type FnRtlEnumerateGenericTableLikeADirectory = unsafe extern "system" fn(
    PRTL_AVL_TABLE,
    PRTL_AVL_MATCH_FUNCTION,
    PVOID,
    ULONG,
    *mut PVOID,
    PULONG,
    PVOID,
) -> PVOID;
pub type FnRtlEnumerateGenericTableWithoutSplaying =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, *mut PVOID) -> PVOID;
pub type FnRtlEnumerateGenericTableWithoutSplayingAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, *mut PVOID) -> PVOID;
pub type FnRtlEqualComputerName =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING) -> BOOLEAN;
pub type FnRtlEqualDomainName =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING) -> BOOLEAN;
pub type FnRtlEqualPrefixSid = unsafe extern "system" fn(PSID, PSID) -> BOOLEAN;
pub type FnRtlEqualSid = unsafe extern "system" fn(PSID, PSID) -> BOOLEAN;
pub type FnRtlEqualString =
    unsafe extern "system" fn(*const STRING, *const STRING, BOOLEAN) -> BOOLEAN;
pub type FnRtlEqualUnicodeString =
    unsafe extern "system" fn(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> BOOLEAN;
pub type FnRtlEraseUnicodeString = unsafe extern "system" fn(PUNICODE_STRING) -> ();
pub type FnRtlEthernetAddressToStringA = unsafe extern "system" fn(*const DL_EUI48, PSTR) -> PSTR;
pub type FnRtlEthernetAddressToStringW = unsafe extern "system" fn(*const DL_EUI48, PWSTR) -> PWSTR;
pub type FnRtlEthernetStringToAddressA =
    unsafe extern "system" fn(PCSTR, *mut PCSTR, *mut DL_EUI48) -> LONG;
pub type FnRtlEthernetStringToAddressW =
    unsafe extern "system" fn(PCWSTR, *mut LPCWSTR, *mut DL_EUI48) -> LONG;
pub type FnRtlExitUserProcess = unsafe extern "system" fn(NTSTATUS) -> ();
pub type FnRtlExitUserThread = unsafe extern "system" fn(NTSTATUS) -> ();
pub type FnRtlExpandEnvironmentStrings =
    unsafe extern "system" fn(PVOID, PWSTR, SIZE_T, PWSTR, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnRtlExpandEnvironmentStrings_U =
    unsafe extern "system" fn(PVOID, PUNICODE_STRING, PUNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnRtlExpandHashTable = unsafe extern "system" fn(PRTL_DYNAMIC_HASH_TABLE) -> BOOLEAN;
pub type FnRtlExtendMemoryBlockLookaside = unsafe extern "system" fn(PVOID, ULONG) -> NTSTATUS;
pub type FnRtlExtractBitMap =
    unsafe extern "system" fn(PRTL_BITMAP, PRTL_BITMAP, ULONG, ULONG) -> ();
pub type FnRtlFillMemory = unsafe extern "system" fn(*mut c_void, usize, u8) -> ();
pub type FnRtlFillMemoryUlong = unsafe extern "system" fn(PVOID, SIZE_T, ULONG) -> ();
pub type FnRtlFillMemoryUlonglong = unsafe extern "system" fn(PVOID, SIZE_T, ULONGLONG) -> ();
pub type FnRtlFindAceByType = unsafe extern "system" fn(PACL, UCHAR, PULONG) -> PVOID;
pub type FnRtlFindCharInUnicodeString =
    unsafe extern "system" fn(ULONG, PUNICODE_STRING, PUNICODE_STRING, PUSHORT) -> NTSTATUS;
pub type FnRtlFindClearBits = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlFindClearBitsAndSet = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlFindClearRuns =
    unsafe extern "system" fn(PRTL_BITMAP, PRTL_BITMAP_RUN, ULONG, BOOLEAN) -> ULONG;
pub type FnRtlFindClosestEncodableLength =
    unsafe extern "system" fn(ULONGLONG, PULONGLONG) -> NTSTATUS;
pub type FnRtlFindExportedRoutineByName = unsafe extern "system" fn(PVOID, PSTR) -> PVOID;
pub type FnRtlFindLastBackwardRunClear =
    unsafe extern "system" fn(PRTL_BITMAP, ULONG, PULONG) -> ULONG;
pub type FnRtlFindLeastSignificantBit = unsafe extern "system" fn(ULONGLONG) -> CCHAR;
pub type FnRtlFindLongestRunClear = unsafe extern "system" fn(PRTL_BITMAP, PULONG) -> ULONG;
pub type FnRtlFindMessage =
    unsafe extern "system" fn(PVOID, ULONG, ULONG, ULONG, *mut PMESSAGE_RESOURCE_ENTRY) -> NTSTATUS;
pub type FnRtlFindMostSignificantBit = unsafe extern "system" fn(ULONGLONG) -> CCHAR;
pub type FnRtlFindNextForwardRunClear =
    unsafe extern "system" fn(PRTL_BITMAP, ULONG, PULONG) -> ULONG;
pub type FnRtlFindSetBits = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlFindSetBitsAndClear = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlFindSetBitsAndClearEx =
    unsafe extern "system" fn(PRTL_BITMAP_EX, ULONG64, ULONG64) -> ULONG64;
pub type FnRtlFindSetBitsEx =
    unsafe extern "system" fn(PRTL_BITMAP_EX, ULONG64, ULONG64) -> ULONG64;
pub type FnRtlFindUnicodeSubstring =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN) -> PWCHAR;
pub type FnRtlFirstEntrySList = unsafe extern "system" fn(*const SLIST_HEADER) -> PSLIST_ENTRY;
pub type FnRtlFirstFreeAce = unsafe extern "system" fn(PACL, *mut PVOID) -> BOOLEAN;
pub type FnRtlFlsAlloc = unsafe extern "system" fn(PFLS_CALLBACK_FUNCTION, PULONG) -> NTSTATUS;
pub type FnRtlFlsFree = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnRtlFlushHeaps = unsafe extern "system" fn() -> ();
pub type FnRtlFlushSecureMemoryCache = unsafe extern "system" fn(PVOID, SIZE_T) -> BOOLEAN;
pub type FnRtlFormatCurrentUserKeyPath = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlFormatMessage = unsafe extern "system" fn(
    PWSTR,
    ULONG,
    BOOLEAN,
    BOOLEAN,
    BOOLEAN,
    *mut va_list,
    PWSTR,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnRtlFormatMessageEx = unsafe extern "system" fn(
    PWSTR,
    ULONG,
    BOOLEAN,
    BOOLEAN,
    BOOLEAN,
    *mut va_list,
    PWSTR,
    ULONG,
    PULONG,
    PPARSE_MESSAGE_CONTEXT,
) -> NTSTATUS;
pub type FnRtlFreeAnsiString = unsafe extern "system" fn(PANSI_STRING) -> ();
pub type FnRtlFreeHandle =
    unsafe extern "system" fn(PRTL_HANDLE_TABLE, PRTL_HANDLE_TABLE_ENTRY) -> BOOLEAN;
pub type FnRtlFreeHeap = unsafe extern "system" fn(PVOID, ULONG, PVOID) -> BOOLEAN;
pub type FnRtlFreeMemoryBlockLookaside = unsafe extern "system" fn(PVOID, PVOID) -> NTSTATUS;
pub type FnRtlFreeOemString = unsafe extern "system" fn(POEM_STRING) -> ();
pub type FnRtlFreeSid = unsafe extern "system" fn(PSID) -> PVOID;
pub type FnRtlFreeUnicodeString = unsafe extern "system" fn(PUNICODE_STRING) -> ();
pub type FnRtlFreeUserStack = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlGUIDFromString = unsafe extern "system" fn(PCUNICODE_STRING, *mut GUID) -> NTSTATUS;
pub type FnRtlGenerate8dot3Name = unsafe extern "system" fn(
    PCUNICODE_STRING,
    BOOLEAN,
    PGENERATE_NAME_CONTEXT,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnRtlGetAce = unsafe extern "system" fn(PACL, ULONG, *mut PVOID) -> NTSTATUS;
pub type FnRtlGetActiveConsoleId = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetAppContainerNamedObjectPath =
    unsafe extern "system" fn(HANDLE, PSID, BOOLEAN, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlGetAppContainerParent = unsafe extern "system" fn(PSID, *mut PSID) -> NTSTATUS;
pub type FnRtlGetAppContainerSidType =
    unsafe extern "system" fn(PSID, PAPPCONTAINER_SID_TYPE) -> NTSTATUS;
pub type FnRtlGetCallersAddress = unsafe extern "system" fn(*mut PVOID, *mut PVOID) -> ();
pub type FnRtlGetCompressionWorkSpaceSize =
    unsafe extern "system" fn(USHORT, PULONG, PULONG) -> NTSTATUS;
pub type FnRtlGetConsoleSessionForegroundProcessId = unsafe extern "system" fn() -> ULONGLONG;
pub type FnRtlGetControlSecurityDescriptor = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR_CONTROL,
    PULONG,
) -> NTSTATUS;
pub type FnRtlGetCriticalSectionRecursionCount =
    unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> ULONG;
pub type FnRtlGetCurrentDirectory_U = unsafe extern "system" fn(ULONG, PWSTR) -> ULONG;
pub type FnRtlGetCurrentPeb = unsafe extern "system" fn() -> PPEB;
pub type FnRtlGetCurrentProcessorNumber = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetCurrentProcessorNumberEx = unsafe extern "system" fn(PPROCESSOR_NUMBER) -> ();
pub type FnRtlGetCurrentServiceSessionId = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetCurrentTransaction = unsafe extern "system" fn() -> HANDLE;
pub type FnRtlGetDaclSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PBOOLEAN, *mut PACL, PBOOLEAN) -> NTSTATUS;
pub type FnRtlGetDeviceFamilyInfoEnum =
    unsafe extern "system" fn(*mut ULONGLONG, *mut DWORD, *mut DWORD) -> ();
pub type FnRtlGetElementGenericTable =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, ULONG) -> PVOID;
pub type FnRtlGetElementGenericTableAvl = unsafe extern "system" fn(PRTL_AVL_TABLE, ULONG) -> PVOID;
pub type FnRtlGetEnabledExtendedFeatures = unsafe extern "system" fn(ULONG64) -> ULONG64;
pub type FnRtlGetExePath = unsafe extern "system" fn() -> PWSTR;
pub type FnRtlGetExtendedContextLength = unsafe extern "system" fn(ULONG, PULONG) -> ULONG;
pub type FnRtlGetExtendedFeaturesMask = unsafe extern "system" fn(PCONTEXT_EX) -> ULONG64;
pub type FnRtlGetFrame = unsafe extern "system" fn() -> PTEB_ACTIVE_FRAME;
pub type FnRtlGetFullPathName_U =
    unsafe extern "system" fn(PWSTR, ULONG, PWSTR, *mut PWSTR) -> ULONG;
pub type FnRtlGetFullPathName_UEx =
    unsafe extern "system" fn(PWSTR, ULONG, PWSTR, *mut PWSTR, *mut ULONG) -> NTSTATUS;
pub type FnRtlGetFullPathName_UstrEx = unsafe extern "system" fn(
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    *mut PUNICODE_STRING,
    *mut SIZE_T,
    PBOOLEAN,
    *mut RTL_PATH_TYPE,
    *mut SIZE_T,
) -> NTSTATUS;
pub type FnRtlGetFunctionTableListHead = unsafe extern "system" fn() -> PLIST_ENTRY;
pub type FnRtlGetGroupSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, *mut PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlGetIntegerAtom = unsafe extern "system" fn(PWSTR, PUSHORT) -> BOOLEAN;
pub type FnRtlGetLastNtStatus = unsafe extern "system" fn() -> NTSTATUS;
pub type FnRtlGetLastWin32Error = unsafe extern "system" fn() -> LONG;
pub type FnRtlGetLengthWithoutLastFullDosOrNtPathElement =
    unsafe extern "system" fn(ULONG, PUNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnRtlGetLengthWithoutTrailingPathSeperators =
    unsafe extern "system" fn(ULONG, PUNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnRtlGetLocaleFileMappingAddress =
    unsafe extern "system" fn(*mut PVOID, PLCID, PLARGE_INTEGER) -> NTSTATUS;
pub type FnRtlGetLongestNtPathLength = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetNativeSystemInformation =
    unsafe extern "system" fn(ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlGetNextEntryHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_CONTEXT,
) -> PRTL_DYNAMIC_HASH_TABLE_ENTRY;
pub type FnRtlGetNtGlobalFlags = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetNtProductType = unsafe extern "system" fn(PNT_PRODUCT_TYPE) -> BOOLEAN;
pub type FnRtlGetNtSystemRoot = unsafe extern "system" fn() -> PWSTR;
pub type FnRtlGetNtVersionNumbers = unsafe extern "system" fn(PULONG, PULONG, PULONG) -> ();
pub type FnRtlGetOwnerSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, *mut PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlGetParentLocaleName =
    unsafe extern "system" fn(PWSTR, PUNICODE_STRING, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnRtlGetPersistedStateLocation = unsafe extern "system" fn(
    PCWSTR,
    PCWSTR,
    PCWSTR,
    STATE_LOCATION_TYPE,
    PWCHAR,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnRtlGetProcessHeaps = unsafe extern "system" fn(ULONG, *mut PVOID) -> ULONG;
pub type FnRtlGetProductInfo =
    unsafe extern "system" fn(DWORD, DWORD, DWORD, DWORD, PDWORD) -> BOOLEAN;
pub type FnRtlGetSaclSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PBOOLEAN, *mut PACL, PBOOLEAN) -> NTSTATUS;
pub type FnRtlGetSearchPath = unsafe extern "system" fn(*mut PWSTR) -> BOOLEAN;
pub type FnRtlGetSecurityDescriptorRMControl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PUCHAR) -> BOOLEAN;
pub type FnRtlGetSetBootStatusData =
    unsafe extern "system" fn(HANDLE, BOOLEAN, RTL_BSD_ITEM_TYPE, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlGetSuiteMask = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetThreadErrorMode = unsafe extern "system" fn() -> ULONG;
pub type FnRtlGetTokenNamedObjectPath =
    unsafe extern "system" fn(HANDLE, PSID, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlGetUnloadEventTrace = unsafe extern "system" fn() -> PRTL_UNLOAD_EVENT_TRACE;
pub type FnRtlGetUnloadEventTraceEx =
    unsafe extern "system" fn(*mut PULONG, *mut PULONG, *mut PVOID) -> ();
pub type FnRtlGetUserInfoHeap =
    unsafe extern "system" fn(PVOID, ULONG, PVOID, *mut PVOID, PULONG) -> BOOLEAN;
pub type FnRtlGetVersion = unsafe extern "system" fn(PRTL_OSVERSIONINFOW) -> NTSTATUS;
pub type FnRtlGrowFunctionTable = unsafe extern "system" fn(PVOID, DWORD) -> ();
pub type FnRtlGuardCheckLongJumpTarget = unsafe extern "system" fn(PVOID, BOOL, PBOOL) -> NTSTATUS;
pub type FnRtlHashUnicodeString =
    unsafe extern "system" fn(PCUNICODE_STRING, BOOLEAN, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlIdentifierAuthoritySid = unsafe extern "system" fn(PSID) -> PSID_IDENTIFIER_AUTHORITY;
pub type FnRtlIdnToAscii = unsafe extern "system" fn(ULONG, PCWSTR, LONG, PWSTR, PLONG) -> NTSTATUS;
pub type FnRtlIdnToNameprepUnicode =
    unsafe extern "system" fn(ULONG, PCWSTR, LONG, PWSTR, PLONG) -> NTSTATUS;
pub type FnRtlIdnToUnicode =
    unsafe extern "system" fn(ULONG, PCWSTR, LONG, PWSTR, PLONG) -> NTSTATUS;
pub type FnRtlImageDirectoryEntryToData =
    unsafe extern "system" fn(PVOID, BOOLEAN, USHORT, PULONG) -> PVOID;
pub type FnRtlImageNtHeader = unsafe extern "system" fn(PVOID) -> PIMAGE_NT_HEADERS;
pub type FnRtlImageNtHeaderEx =
    unsafe extern "system" fn(ULONG, PVOID, ULONG64, *mut PIMAGE_NT_HEADERS) -> NTSTATUS;
pub type FnRtlImageRvaToSection =
    unsafe extern "system" fn(PIMAGE_NT_HEADERS, PVOID, ULONG) -> PIMAGE_SECTION_HEADER;
pub type FnRtlImageRvaToVa =
    unsafe extern "system" fn(PIMAGE_NT_HEADERS, PVOID, ULONG, *mut PIMAGE_SECTION_HEADER) -> PVOID;
pub type FnRtlImpersonateSelf = unsafe extern "system" fn(SECURITY_IMPERSONATION_LEVEL) -> NTSTATUS;
pub type FnRtlImpersonateSelfEx =
    unsafe extern "system" fn(SECURITY_IMPERSONATION_LEVEL, ACCESS_MASK, PHANDLE) -> NTSTATUS;
pub type FnRtlInitAnsiString = unsafe extern "system" fn(PANSI_STRING, PCSZ) -> ();
pub type FnRtlInitAnsiStringEx = unsafe extern "system" fn(PANSI_STRING, PCSZ) -> NTSTATUS;
pub type FnRtlInitBarrier = unsafe extern "system" fn(PRTL_BARRIER, ULONG, ULONG) -> NTSTATUS;
pub type FnRtlInitCodePageTable = unsafe extern "system" fn(PUSHORT, PCPTABLEINFO) -> ();
pub type FnRtlInitEnumerationHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
) -> BOOLEAN;
pub type FnRtlInitNlsTables =
    unsafe extern "system" fn(PUSHORT, PUSHORT, PUSHORT, PNLSTABLEINFO) -> ();
pub type FnRtlInitString = unsafe extern "system" fn(PSTRING, PCSZ) -> ();
pub type FnRtlInitStringEx = unsafe extern "system" fn(PSTRING, PCSZ) -> NTSTATUS;
pub type FnRtlInitStrongEnumerationHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
) -> BOOLEAN;
pub type FnRtlInitUnicodeString = unsafe extern "system" fn(PUNICODE_STRING, PCWSTR) -> ();
pub type FnRtlInitUnicodeStringEx = unsafe extern "system" fn(PUNICODE_STRING, PCWSTR) -> NTSTATUS;
pub type FnRtlInitWeakEnumerationHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
) -> BOOLEAN;
pub type FnRtlInitializeBitMap = unsafe extern "system" fn(PRTL_BITMAP, PULONG, ULONG) -> ();
pub type FnRtlInitializeBitMapEx =
    unsafe extern "system" fn(PRTL_BITMAP_EX, PULONG64, ULONG64) -> ();
pub type FnRtlInitializeConditionVariable =
    unsafe extern "system" fn(PRTL_CONDITION_VARIABLE) -> ();
pub type FnRtlInitializeContext =
    unsafe extern "system" fn(HANDLE, PCONTEXT, PVOID, PVOID, PVOID) -> ();
pub type FnRtlInitializeCriticalSection =
    unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> NTSTATUS;
pub type FnRtlInitializeCriticalSectionAndSpinCount =
    unsafe extern "system" fn(PRTL_CRITICAL_SECTION, ULONG) -> NTSTATUS;
pub type FnRtlInitializeExtendedContext =
    unsafe extern "system" fn(PCONTEXT, ULONG, *mut PCONTEXT_EX) -> ULONG;
pub type FnRtlInitializeGenericTable = unsafe extern "system" fn(
    PRTL_GENERIC_TABLE,
    PRTL_GENERIC_COMPARE_ROUTINE,
    PRTL_GENERIC_ALLOCATE_ROUTINE,
    PRTL_GENERIC_FREE_ROUTINE,
    PVOID,
) -> ();
pub type FnRtlInitializeGenericTableAvl = unsafe extern "system" fn(
    PRTL_AVL_TABLE,
    PRTL_AVL_COMPARE_ROUTINE,
    PRTL_AVL_ALLOCATE_ROUTINE,
    PRTL_AVL_FREE_ROUTINE,
    PVOID,
) -> ();
pub type FnRtlInitializeHandleTable =
    unsafe extern "system" fn(ULONG, ULONG, PRTL_HANDLE_TABLE) -> ();
pub type FnRtlInitializeResource = unsafe extern "system" fn(PRTL_RESOURCE) -> ();
pub type FnRtlInitializeSListHead = unsafe extern "system" fn(PSLIST_HEADER) -> ();
pub type FnRtlInitializeSRWLock = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlInitializeSid =
    unsafe extern "system" fn(PSID, PSID_IDENTIFIER_AUTHORITY, UCHAR) -> NTSTATUS;
pub type FnRtlInitializeSidEx =
    unsafe extern "system" fn(PSID, PSID_IDENTIFIER_AUTHORITY, UCHAR) -> NTSTATUS;
pub type FnRtlInsertElementGenericTable =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, PVOID, CLONG, PBOOLEAN) -> PVOID;
pub type FnRtlInsertElementGenericTableAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, PVOID, CLONG, PBOOLEAN) -> PVOID;
pub type FnRtlInsertElementGenericTableFull = unsafe extern "system" fn(
    PRTL_GENERIC_TABLE,
    PVOID,
    CLONG,
    PBOOLEAN,
    PVOID,
    TABLE_SEARCH_RESULT,
) -> PVOID;
pub type FnRtlInsertElementGenericTableFullAvl = unsafe extern "system" fn(
    PRTL_AVL_TABLE,
    PVOID,
    CLONG,
    PBOOLEAN,
    PVOID,
    TABLE_SEARCH_RESULT,
) -> PVOID;
pub type FnRtlInsertEntryHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENTRY,
    ULONG_PTR,
    PRTL_DYNAMIC_HASH_TABLE_CONTEXT,
) -> BOOLEAN;
pub type FnRtlInstallFunctionTableCallback = unsafe extern "system" fn(
    DWORD64,
    DWORD64,
    DWORD,
    PGET_RUNTIME_FUNCTION_CALLBACK,
    PVOID,
    PCWSTR,
) -> BOOLEAN;
pub type FnRtlInt64ToUnicodeString =
    unsafe extern "system" fn(ULONGLONG, ULONG, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlIntegerToChar = unsafe extern "system" fn(ULONG, ULONG, LONG, PSTR) -> NTSTATUS;
pub type FnRtlIntegerToUnicodeString =
    unsafe extern "system" fn(ULONG, ULONG, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlInterlockedClearBitRun = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ();
pub type FnRtlInterlockedFlushSList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnRtlInterlockedPopEntrySList = unsafe extern "system" fn(PSLIST_HEADER) -> PSLIST_ENTRY;
pub type FnRtlInterlockedPushEntrySList =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY) -> PSLIST_ENTRY;
pub type FnRtlInterlockedPushListSListEx =
    unsafe extern "system" fn(PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, DWORD) -> PSLIST_ENTRY;
pub type FnRtlInterlockedSetBitRun = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ();
pub type FnRtlIpv4AddressToStringA = unsafe extern "system" fn(*const IN_ADDR, PSTR) -> PSTR;
pub type FnRtlIpv4AddressToStringExA =
    unsafe extern "system" fn(*const IN_ADDR, USHORT, PSTR, PULONG) -> LONG;
pub type FnRtlIpv4AddressToStringExW =
    unsafe extern "system" fn(*const IN_ADDR, USHORT, PWSTR, PULONG) -> LONG;
pub type FnRtlIpv4AddressToStringW = unsafe extern "system" fn(*const IN_ADDR, PWSTR) -> PWSTR;
pub type FnRtlIpv4StringToAddressA =
    unsafe extern "system" fn(PCSTR, BOOLEAN, *mut PCSTR, *mut IN_ADDR) -> LONG;
pub type FnRtlIpv4StringToAddressExA =
    unsafe extern "system" fn(PCSTR, BOOLEAN, *mut IN_ADDR, PUSHORT) -> LONG;
pub type FnRtlIpv4StringToAddressExW =
    unsafe extern "system" fn(PCWSTR, BOOLEAN, *mut IN_ADDR, PUSHORT) -> LONG;
pub type FnRtlIpv4StringToAddressW =
    unsafe extern "system" fn(PCWSTR, BOOLEAN, *mut LPCWSTR, *mut IN_ADDR) -> LONG;
pub type FnRtlIpv6AddressToStringA = unsafe extern "system" fn(*const IN6_ADDR, PSTR) -> PSTR;
pub type FnRtlIpv6AddressToStringExA =
    unsafe extern "system" fn(*const IN6_ADDR, ULONG, USHORT, PSTR, PULONG) -> LONG;
pub type FnRtlIpv6AddressToStringExW =
    unsafe extern "system" fn(*const IN6_ADDR, ULONG, USHORT, PWSTR, PULONG) -> LONG;
pub type FnRtlIpv6AddressToStringW = unsafe extern "system" fn(*const IN6_ADDR, PWSTR) -> PWSTR;
pub type FnRtlIpv6StringToAddressA =
    unsafe extern "system" fn(PCSTR, *mut PCSTR, *mut IN6_ADDR) -> LONG;
pub type FnRtlIpv6StringToAddressExA =
    unsafe extern "system" fn(PCSTR, *mut IN6_ADDR, PULONG, PUSHORT) -> LONG;
pub type FnRtlIpv6StringToAddressExW =
    unsafe extern "system" fn(PCWSTR, *mut IN6_ADDR, PULONG, PUSHORT) -> LONG;
pub type FnRtlIpv6StringToAddressW =
    unsafe extern "system" fn(PCWSTR, *mut PCWSTR, *mut IN6_ADDR) -> LONG;
pub type FnRtlIsCapabilitySid = unsafe extern "system" fn(PSID) -> BOOLEAN;
pub type FnRtlIsCloudFilesPlaceholder = unsafe extern "system" fn(ULONG, ULONG) -> BOOLEAN;
pub type FnRtlIsCriticalSectionLocked = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> LOGICAL;
pub type FnRtlIsCriticalSectionLockedByThread =
    unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> LOGICAL;
pub type FnRtlIsCurrentProcess = unsafe extern "system" fn(HANDLE) -> BOOLEAN;
pub type FnRtlIsCurrentThread = unsafe extern "system" fn(HANDLE) -> BOOLEAN;
pub type FnRtlIsCurrentThreadAttachExempt = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlIsDosDeviceName_U = unsafe extern "system" fn(PWSTR) -> ULONG;
pub type FnRtlIsElevatedRid = unsafe extern "system" fn(PSID_AND_ATTRIBUTES) -> BOOLEAN;
pub type FnRtlIsGenericTableEmpty = unsafe extern "system" fn(PRTL_GENERIC_TABLE) -> BOOLEAN;
pub type FnRtlIsGenericTableEmptyAvl = unsafe extern "system" fn(PRTL_AVL_TABLE) -> BOOLEAN;
pub type FnRtlIsMultiSessionSku = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlIsMultiUsersInSessionSku = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlIsNameInExpression =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN, PWCH) -> BOOLEAN;
pub type FnRtlIsNameInUnUpcasedExpression =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN, PWCH) -> BOOLEAN;
pub type FnRtlIsNonEmptyDirectoryReparsePointAllowed = unsafe extern "system" fn(ULONG) -> BOOLEAN;
pub type FnRtlIsNormalizedString =
    unsafe extern "system" fn(ULONG, PCWSTR, LONG, PBOOLEAN) -> NTSTATUS;
pub type FnRtlIsPackageSid = unsafe extern "system" fn(PSID) -> BOOLEAN;
pub type FnRtlIsParentOfChildAppContainer = unsafe extern "system" fn(PSID, PSID) -> NTSTATUS;
pub type FnRtlIsPartialPlaceholder = unsafe extern "system" fn(ULONG, ULONG) -> BOOLEAN;
pub type FnRtlIsPartialPlaceholderFileHandle =
    unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnRtlIsPartialPlaceholderFileInfo =
    unsafe extern "system" fn(*const c_void, FILE_INFORMATION_CLASS, PBOOLEAN) -> NTSTATUS;
pub type FnRtlIsProcessorFeaturePresent = unsafe extern "system" fn(ULONG) -> BOOLEAN;
pub type FnRtlIsStateSeparationEnabled = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlIsTextUnicode = unsafe extern "system" fn(PVOID, ULONG, PULONG) -> BOOLEAN;
pub type FnRtlIsThreadWithinLoaderCallout = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlIsUntrustedObject = unsafe extern "system" fn(HANDLE, PVOID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlIsValidHandle =
    unsafe extern "system" fn(PRTL_HANDLE_TABLE, PRTL_HANDLE_TABLE_ENTRY) -> BOOLEAN;
pub type FnRtlIsValidIndexHandle =
    unsafe extern "system" fn(PRTL_HANDLE_TABLE, ULONG, *mut PRTL_HANDLE_TABLE_ENTRY) -> BOOLEAN;
pub type FnRtlIsValidLocaleName = unsafe extern "system" fn(PWSTR, ULONG) -> BOOLEAN;
pub type FnRtlIsValidProcessTrustLabelSid = unsafe extern "system" fn(PSID) -> BOOLEAN;
pub type FnRtlKnownExceptionFilter = unsafe extern "system" fn(PEXCEPTION_POINTERS) -> LONG;
pub type FnRtlLCIDToCultureName = unsafe extern "system" fn(LCID, PUNICODE_STRING) -> BOOLEAN;
pub type FnRtlLargeIntegerToChar =
    unsafe extern "system" fn(PLARGE_INTEGER, ULONG, LONG, PSTR) -> NTSTATUS;
pub type FnRtlLcidToLocaleName =
    unsafe extern "system" fn(LCID, PUNICODE_STRING, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnRtlLeaveCriticalSection = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> NTSTATUS;
pub type FnRtlLengthRequiredSid = unsafe extern "system" fn(ULONG) -> ULONG;
pub type FnRtlLengthSecurityDescriptor = unsafe extern "system" fn(PSECURITY_DESCRIPTOR) -> ULONG;
pub type FnRtlLengthSid = unsafe extern "system" fn(PSID) -> ULONG;
pub type FnRtlLocalTimeToSystemTime =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnRtlLocaleNameToLcid = unsafe extern "system" fn(PWSTR, PLCID, ULONG) -> NTSTATUS;
pub type FnRtlLocateExtendedFeature =
    unsafe extern "system" fn(PCONTEXT_EX, ULONG, PULONG) -> PVOID;
pub type FnRtlLocateLegacyContext = unsafe extern "system" fn(PCONTEXT_EX, PULONG) -> PCONTEXT;
pub type FnRtlLockBootStatusData = unsafe extern "system" fn(PHANDLE) -> NTSTATUS;
pub type FnRtlLockCurrentThread = unsafe extern "system" fn() -> NTSTATUS;
pub type FnRtlLockHeap = unsafe extern "system" fn(PVOID) -> BOOLEAN;
pub type FnRtlLockMemoryBlockLookaside = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlLockMemoryZone = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlLockModuleSection = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlLookupAtomInAtomTable =
    unsafe extern "system" fn(PVOID, PWSTR, PRTL_ATOM) -> NTSTATUS;
pub type FnRtlLookupElementGenericTable =
    unsafe extern "system" fn(PRTL_GENERIC_TABLE, PVOID) -> PVOID;
pub type FnRtlLookupElementGenericTableAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, PVOID) -> PVOID;
pub type FnRtlLookupElementGenericTableFull = unsafe extern "system" fn(
    PRTL_GENERIC_TABLE,
    PVOID,
    *mut PVOID,
    *mut TABLE_SEARCH_RESULT,
) -> PVOID;
pub type FnRtlLookupElementGenericTableFullAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, PVOID, *mut PVOID, *mut TABLE_SEARCH_RESULT) -> PVOID;
pub type FnRtlLookupEntryHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    ULONG_PTR,
    PRTL_DYNAMIC_HASH_TABLE_CONTEXT,
) -> PRTL_DYNAMIC_HASH_TABLE_ENTRY;
pub type FnRtlLookupFirstMatchingElementGenericTableAvl =
    unsafe extern "system" fn(PRTL_AVL_TABLE, PVOID, *mut PVOID) -> PVOID;
pub type FnRtlLookupFunctionEntry =
    unsafe extern "system" fn(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE) -> PRUNTIME_FUNCTION;
pub type FnRtlMakeSelfRelativeSD =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG) -> NTSTATUS;
pub type FnRtlMapGenericMask = unsafe extern "system" fn(PACCESS_MASK, PGENERIC_MAPPING) -> ();
pub type FnRtlMoveMemory = unsafe extern "system" fn(*mut c_void, *const c_void, usize) -> ();
pub type FnRtlMultiByteToUnicodeN =
    unsafe extern "system" fn(PWCH, ULONG, PULONG, *const CHAR, ULONG) -> NTSTATUS;
pub type FnRtlMultiByteToUnicodeSize =
    unsafe extern "system" fn(PULONG, *const CHAR, ULONG) -> NTSTATUS;
pub type FnRtlMultipleAllocateHeap =
    unsafe extern "system" fn(PVOID, ULONG, SIZE_T, ULONG, *mut PVOID) -> ULONG;
pub type FnRtlMultipleFreeHeap =
    unsafe extern "system" fn(PVOID, ULONG, ULONG, *mut PVOID) -> ULONG;
pub type FnRtlNewInstanceSecurityObject = unsafe extern "system" fn(
    BOOLEAN,
    BOOLEAN,
    PLUID,
    PLUID,
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    BOOLEAN,
    HANDLE,
    PGENERIC_MAPPING,
) -> NTSTATUS;
pub type FnRtlNewSecurityObject = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    BOOLEAN,
    HANDLE,
    PGENERIC_MAPPING,
) -> NTSTATUS;
pub type FnRtlNewSecurityObjectEx = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    *mut GUID,
    BOOLEAN,
    ULONG,
    HANDLE,
    PGENERIC_MAPPING,
) -> NTSTATUS;
pub type FnRtlNewSecurityObjectWithMultipleInheritance = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    ULONG,
    BOOLEAN,
    ULONG,
    HANDLE,
    PGENERIC_MAPPING,
) -> NTSTATUS;
pub type FnRtlNormalizeProcessParams =
    unsafe extern "system" fn(PRTL_USER_PROCESS_PARAMETERS) -> PRTL_USER_PROCESS_PARAMETERS;
pub type FnRtlNormalizeString =
    unsafe extern "system" fn(ULONG, PCWSTR, LONG, PWSTR, PLONG) -> NTSTATUS;
pub type FnRtlNtStatusToDosError = unsafe extern "system" fn(NTSTATUS) -> ULONG;
pub type FnRtlNtStatusToDosErrorNoTeb = unsafe extern "system" fn(NTSTATUS) -> ULONG;
pub type FnRtlNumberGenericTableElements = unsafe extern "system" fn(PRTL_GENERIC_TABLE) -> ULONG;
pub type FnRtlNumberGenericTableElementsAvl = unsafe extern "system" fn(PRTL_AVL_TABLE) -> ULONG;
pub type FnRtlNumberOfClearBits = unsafe extern "system" fn(PRTL_BITMAP) -> ULONG;
pub type FnRtlNumberOfClearBitsInRange =
    unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlNumberOfSetBits = unsafe extern "system" fn(PRTL_BITMAP) -> ULONG;
pub type FnRtlNumberOfSetBitsInRange =
    unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ULONG;
pub type FnRtlNumberOfSetBitsUlongPtr = unsafe extern "system" fn(ULONG_PTR) -> ULONG;
pub type FnRtlOemStringToUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PCOEM_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlOemToUnicodeN =
    unsafe extern "system" fn(PWCH, ULONG, PULONG, PCCH, ULONG) -> NTSTATUS;
pub type FnRtlOpenCurrentUser = unsafe extern "system" fn(ACCESS_MASK, PHANDLE) -> NTSTATUS;
pub type FnRtlOsDeploymentState = unsafe extern "system" fn(DWORD) -> OS_DEPLOYEMENT_STATE_VALUES;
pub type FnRtlOwnerAcesPresent = unsafe extern "system" fn(PACL) -> BOOLEAN;
pub type FnRtlPcToFileHeader = unsafe extern "system" fn(PVOID, *mut PVOID) -> PVOID;
pub type FnRtlPinAtomInAtomTable = unsafe extern "system" fn(PVOID, RTL_ATOM) -> NTSTATUS;
pub type FnRtlPopFrame = unsafe extern "system" fn(PTEB_ACTIVE_FRAME) -> ();
pub type FnRtlPrefixString =
    unsafe extern "system" fn(*const STRING, *const STRING, BOOLEAN) -> BOOLEAN;
pub type FnRtlPrefixUnicodeString =
    unsafe extern "system" fn(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> BOOLEAN;
pub type FnRtlProtectHeap = unsafe extern "system" fn(PVOID, BOOLEAN) -> ();
pub type FnRtlPushFrame = unsafe extern "system" fn(PTEB_ACTIVE_FRAME) -> ();
pub type FnRtlQueryAtomInAtomTable =
    unsafe extern "system" fn(PVOID, RTL_ATOM, PULONG, PULONG, PWSTR, PULONG) -> NTSTATUS;
pub type FnRtlQueryCriticalSectionOwner = unsafe extern "system" fn(HANDLE) -> HANDLE;
pub type FnRtlQueryDepthSList = unsafe extern "system" fn(PSLIST_HEADER) -> WORD;
pub type FnRtlQueryElevationFlags = unsafe extern "system" fn(PRTL_ELEVATION_FLAGS) -> NTSTATUS;
pub type FnRtlQueryEnvironmentVariable =
    unsafe extern "system" fn(PVOID, PWSTR, SIZE_T, PWSTR, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnRtlQueryEnvironmentVariable_U =
    unsafe extern "system" fn(PVOID, PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlQueryHeapInformation =
    unsafe extern "system" fn(PVOID, HEAP_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnRtlQueryImageMitigationPolicy =
    unsafe extern "system" fn(PWSTR, IMAGE_MITIGATION_POLICY, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnRtlQueryInformationAcl =
    unsafe extern "system" fn(PACL, PVOID, ULONG, ACL_INFORMATION_CLASS) -> NTSTATUS;
pub type FnRtlQueryPackageClaims = unsafe extern "system" fn(
    HANDLE,
    PWSTR,
    PSIZE_T,
    PWSTR,
    PSIZE_T,
    *mut GUID,
    PPS_PKG_CLAIM,
    PULONG64,
) -> NTSTATUS;
pub type FnRtlQueryPerformanceCounter = unsafe extern "system" fn(PLARGE_INTEGER) -> LOGICAL;
pub type FnRtlQueryPerformanceFrequency = unsafe extern "system" fn(PLARGE_INTEGER) -> LOGICAL;
pub type FnRtlQueryProcessDebugInformation =
    unsafe extern "system" fn(HANDLE, ULONG, PRTL_DEBUG_INFORMATION) -> NTSTATUS;
pub type FnRtlQueryProtectedPolicy = unsafe extern "system" fn(*mut GUID, PULONG_PTR) -> NTSTATUS;
pub type FnRtlQueryRegistryValues =
    unsafe extern "system" fn(ULONG, PCWSTR, PRTL_QUERY_REGISTRY_TABLE, PVOID, PVOID) -> NTSTATUS;
pub type FnRtlQueryRegistryValuesEx =
    unsafe extern "system" fn(ULONG, PWSTR, PRTL_QUERY_REGISTRY_TABLE, PVOID, PVOID) -> NTSTATUS;
pub type FnRtlQuerySecurityObject = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnRtlQueryTagHeap =
    unsafe extern "system" fn(PVOID, ULONG, USHORT, BOOLEAN, PRTL_HEAP_TAG_INFO) -> PWSTR;
pub type FnRtlQueryThreadProfiling = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnRtlQueryTimeZoneInformation =
    unsafe extern "system" fn(PRTL_TIME_ZONE_INFORMATION) -> NTSTATUS;
pub type FnRtlQueryValidationRunlevel = unsafe extern "system" fn(PUNICODE_STRING) -> ULONG;
pub type FnRtlQueueApcWow64Thread =
    unsafe extern "system" fn(HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS;
pub type FnRtlQueueWorkItem =
    unsafe extern "system" fn(WORKERCALLBACKFUNC, PVOID, ULONG) -> NTSTATUS;
pub type FnRtlRaiseException = unsafe extern "system" fn(PEXCEPTION_RECORD) -> ();
pub type FnRtlRaiseStatus = unsafe extern "system" fn(NTSTATUS) -> ();
pub type FnRtlRandom = unsafe extern "system" fn(PULONG) -> ULONG;
pub type FnRtlRandomEx = unsafe extern "system" fn(PULONG) -> ULONG;
pub type FnRtlRbInsertNodeEx =
    unsafe extern "system" fn(PRTL_RB_TREE, PRTL_BALANCED_NODE, BOOLEAN, PRTL_BALANCED_NODE) -> ();
pub type FnRtlRbRemoveNode = unsafe extern "system" fn(PRTL_RB_TREE, PRTL_BALANCED_NODE) -> ();
pub type FnRtlReAllocateHeap = unsafe extern "system" fn(PVOID, ULONG, PVOID, SIZE_T) -> PVOID;
pub type FnRtlReadThreadProfilingData =
    unsafe extern "system" fn(HANDLE, ULONG, PPERFORMANCE_DATA) -> NTSTATUS;
pub type FnRtlRealPredecessor = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlRealSuccessor = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlRegisterSecureMemoryCacheCallback =
    unsafe extern "system" fn(PRTL_SECURE_MEMORY_CACHE_CALLBACK) -> NTSTATUS;
pub type FnRtlRegisterThreadWithCsrss = unsafe extern "system" fn() -> NTSTATUS;
pub type FnRtlRegisterWait = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    WAITORTIMERCALLBACKFUNC,
    PVOID,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnRtlReleasePebLock = unsafe extern "system" fn() -> ();
pub type FnRtlReleasePrivilege = unsafe extern "system" fn(PVOID) -> ();
pub type FnRtlReleaseRelativeName = unsafe extern "system" fn(PRTL_RELATIVE_NAME_U) -> ();
pub type FnRtlReleaseResource = unsafe extern "system" fn(PRTL_RESOURCE) -> ();
pub type FnRtlReleaseSRWLockExclusive = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlReleaseSRWLockShared = unsafe extern "system" fn(PRTL_SRWLOCK) -> ();
pub type FnRtlRemoteCall = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PVOID,
    ULONG,
    PULONG_PTR,
    BOOLEAN,
    BOOLEAN,
) -> NTSTATUS;
pub type FnRtlRemoveEntryHashTable = unsafe extern "system" fn(
    PRTL_DYNAMIC_HASH_TABLE,
    PRTL_DYNAMIC_HASH_TABLE_ENTRY,
    PRTL_DYNAMIC_HASH_TABLE_CONTEXT,
) -> BOOLEAN;
pub type FnRtlRemovePrivileges = unsafe extern "system" fn(HANDLE, PULONG, ULONG) -> NTSTATUS;
pub type FnRtlRemoveVectoredContinueHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnRtlRemoveVectoredExceptionHandler = unsafe extern "system" fn(PVOID) -> ULONG;
pub type FnRtlReplaceSidInSd =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSID, PSID, *mut ULONG) -> NTSTATUS;
pub type FnRtlReportException =
    unsafe extern "system" fn(PEXCEPTION_RECORD, PCONTEXT, ULONG) -> NTSTATUS;
pub type FnRtlReportExceptionEx =
    unsafe extern "system" fn(PEXCEPTION_RECORD, PCONTEXT, ULONG, PLARGE_INTEGER) -> NTSTATUS;
pub type FnRtlReportSilentProcessExit = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnRtlResetMemoryBlockLookaside = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlResetMemoryZone = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlResetRtlTranslations = unsafe extern "system" fn(PNLSTABLEINFO) -> ();
pub type FnRtlRestoreContext = unsafe extern "system" fn(PCONTEXT, *mut EXCEPTION_RECORD) -> ();
pub type FnRtlRestoreLastWin32Error = unsafe extern "system" fn(LONG) -> ();
pub type FnRtlRunDecodeUnicodeString = unsafe extern "system" fn(UCHAR, PUNICODE_STRING) -> ();
pub type FnRtlRunEncodeUnicodeString = unsafe extern "system" fn(PUCHAR, PUNICODE_STRING) -> ();
pub type FnRtlSecondsSince1970ToTime = unsafe extern "system" fn(ULONG, PLARGE_INTEGER) -> ();
pub type FnRtlSecondsSince1980ToTime = unsafe extern "system" fn(ULONG, PLARGE_INTEGER) -> ();
pub type FnRtlSelfRelativeToAbsoluteSD = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    PULONG,
    PACL,
    PULONG,
    PACL,
    PULONG,
    PSID,
    PULONG,
    PSID,
    PULONG,
) -> NTSTATUS;
pub type FnRtlSelfRelativeToAbsoluteSD2 =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PULONG) -> NTSTATUS;
pub type FnRtlSendMsgToSm = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnRtlSetAllBits = unsafe extern "system" fn(PRTL_BITMAP) -> ();
pub type FnRtlSetAttributesSecurityDescriptor = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL,
    PULONG,
) -> NTSTATUS;
pub type FnRtlSetBit = unsafe extern "system" fn(PRTL_BITMAP, ULONG) -> ();
pub type FnRtlSetBitEx = unsafe extern "system" fn(PRTL_BITMAP_EX, ULONG64) -> ();
pub type FnRtlSetBits = unsafe extern "system" fn(PRTL_BITMAP, ULONG, ULONG) -> ();
pub type FnRtlSetControlSecurityDescriptor = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL,
    SECURITY_DESCRIPTOR_CONTROL,
) -> NTSTATUS;
pub type FnRtlSetCriticalSectionSpinCount =
    unsafe extern "system" fn(PRTL_CRITICAL_SECTION, ULONG) -> ULONG;
pub type FnRtlSetCurrentDirectory_U = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlSetCurrentEnvironment = unsafe extern "system" fn(PVOID, *mut PVOID) -> NTSTATUS;
pub type FnRtlSetCurrentTransaction = unsafe extern "system" fn(HANDLE) -> LOGICAL;
pub type FnRtlSetDaclSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetEnvironmentStrings = unsafe extern "system" fn(PWCHAR, SIZE_T) -> NTSTATUS;
pub type FnRtlSetEnvironmentVar =
    unsafe extern "system" fn(*mut PWSTR, PWSTR, SIZE_T, PWSTR, SIZE_T) -> NTSTATUS;
pub type FnRtlSetEnvironmentVariable =
    unsafe extern "system" fn(*mut PVOID, PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlSetExtendedFeaturesMask = unsafe extern "system" fn(PCONTEXT_EX, ULONG64) -> ();
pub type FnRtlSetGroupSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSID, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetHeapInformation =
    unsafe extern "system" fn(PVOID, HEAP_INFORMATION_CLASS, PVOID, SIZE_T) -> NTSTATUS;
pub type FnRtlSetImageMitigationPolicy =
    unsafe extern "system" fn(PWSTR, IMAGE_MITIGATION_POLICY, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnRtlSetInformationAcl =
    unsafe extern "system" fn(PACL, PVOID, ULONG, ACL_INFORMATION_CLASS) -> NTSTATUS;
pub type FnRtlSetIoCompletionCallback =
    unsafe extern "system" fn(HANDLE, APC_CALLBACK_FUNCTION, ULONG) -> NTSTATUS;
pub type FnRtlSetLastWin32Error = unsafe extern "system" fn(LONG) -> ();
pub type FnRtlSetLastWin32ErrorAndNtStatusFromNtStatus = unsafe extern "system" fn(NTSTATUS) -> ();
pub type FnRtlSetOwnerSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PSID, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetPortableOperatingSystem = unsafe extern "system" fn(BOOLEAN) -> NTSTATUS;
pub type FnRtlSetProcessIsCritical =
    unsafe extern "system" fn(BOOLEAN, PBOOLEAN, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetProtectedPolicy =
    unsafe extern "system" fn(*mut GUID, ULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnRtlSetSaclSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetSearchPathMode = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnRtlSetSecurityDescriptorRMControl =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, PUCHAR) -> ();
pub type FnRtlSetSecurityObject = unsafe extern "system" fn(
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    PGENERIC_MAPPING,
    HANDLE,
) -> NTSTATUS;
pub type FnRtlSetSecurityObjectEx = unsafe extern "system" fn(
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    ULONG,
    PGENERIC_MAPPING,
    HANDLE,
) -> NTSTATUS;
pub type FnRtlSetThreadErrorMode = unsafe extern "system" fn(ULONG, PULONG) -> NTSTATUS;
pub type FnRtlSetThreadIsCritical =
    unsafe extern "system" fn(BOOLEAN, PBOOLEAN, BOOLEAN) -> NTSTATUS;
pub type FnRtlSetThreadPoolStartFunc =
    unsafe extern "system" fn(PRTL_START_POOL_THREAD, PRTL_EXIT_POOL_THREAD) -> NTSTATUS;
pub type FnRtlSetTimeZoneInformation =
    unsafe extern "system" fn(PRTL_TIME_ZONE_INFORMATION) -> NTSTATUS;
pub type FnRtlSetUnhandledExceptionFilter =
    unsafe extern "system" fn(PRTLP_UNHANDLED_EXCEPTION_FILTER) -> ();
pub type FnRtlSetUserFlagsHeap =
    unsafe extern "system" fn(PVOID, ULONG, PVOID, ULONG, ULONG) -> BOOLEAN;
pub type FnRtlSetUserValueHeap = unsafe extern "system" fn(PVOID, ULONG, PVOID, PVOID) -> BOOLEAN;
pub type FnRtlSidDominates = unsafe extern "system" fn(PSID, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlSidDominatesForTrust = unsafe extern "system" fn(PSID, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlSidEqualLevel = unsafe extern "system" fn(PSID, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlSidHashInitialize =
    unsafe extern "system" fn(PSID_AND_ATTRIBUTES, ULONG, PSID_AND_ATTRIBUTES_HASH) -> NTSTATUS;
pub type FnRtlSidHashLookup =
    unsafe extern "system" fn(PSID_AND_ATTRIBUTES_HASH, PSID) -> PSID_AND_ATTRIBUTES;
pub type FnRtlSidIsHigherLevel = unsafe extern "system" fn(PSID, PSID, PBOOLEAN) -> NTSTATUS;
pub type FnRtlSizeHeap = unsafe extern "system" fn(PVOID, ULONG, PVOID) -> SIZE_T;
pub type FnRtlSleepConditionVariableCS = unsafe extern "system" fn(
    PRTL_CONDITION_VARIABLE,
    PRTL_CRITICAL_SECTION,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnRtlSleepConditionVariableSRW = unsafe extern "system" fn(
    PRTL_CONDITION_VARIABLE,
    PRTL_SRWLOCK,
    PLARGE_INTEGER,
    ULONG,
) -> NTSTATUS;
pub type FnRtlSplay = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlStringFromGUID = unsafe extern "system" fn(*const GUID, PUNICODE_STRING) -> NTSTATUS;
pub type FnRtlStringFromGUIDEx =
    unsafe extern "system" fn(*mut GUID, PUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlStronglyEnumerateEntryHashTable =
    unsafe extern "system" fn(
        PRTL_DYNAMIC_HASH_TABLE,
        PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
    ) -> PRTL_DYNAMIC_HASH_TABLE_ENTRY;
pub type FnRtlSubAuthorityCountSid = unsafe extern "system" fn(PSID) -> PUCHAR;
pub type FnRtlSubAuthoritySid = unsafe extern "system" fn(PSID, ULONG) -> PULONG;
pub type FnRtlSubtreePredecessor = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlSubtreeSuccessor = unsafe extern "system" fn(PRTL_SPLAY_LINKS) -> PRTL_SPLAY_LINKS;
pub type FnRtlSwitchedVVI =
    unsafe extern "system" fn(PRTL_OSVERSIONINFOEXW, DWORD, ULONGLONG) -> DWORD;
pub type FnRtlSystemTimeToLocalTime =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnRtlTestBit = unsafe extern "system" fn(PRTL_BITMAP, ULONG) -> BOOLEAN;
pub type FnRtlTestBitEx = unsafe extern "system" fn(PRTL_BITMAP_EX, ULONG64) -> BOOLEAN;
pub type FnRtlTestProtectedAccess =
    unsafe extern "system" fn(PS_PROTECTION, PS_PROTECTION) -> BOOLEAN;
pub type FnRtlTimeFieldsToTime = unsafe extern "system" fn(PTIME_FIELDS, PLARGE_INTEGER) -> BOOLEAN;
pub type FnRtlTimeToElapsedTimeFields =
    unsafe extern "system" fn(PLARGE_INTEGER, PTIME_FIELDS) -> ();
pub type FnRtlTimeToSecondsSince1970 = unsafe extern "system" fn(PLARGE_INTEGER, PULONG) -> BOOLEAN;
pub type FnRtlTimeToSecondsSince1980 = unsafe extern "system" fn(PLARGE_INTEGER, PULONG) -> BOOLEAN;
pub type FnRtlTimeToTimeFields = unsafe extern "system" fn(PLARGE_INTEGER, PTIME_FIELDS) -> ();
pub type FnRtlTryAcquirePebLock = unsafe extern "system" fn() -> LOGICAL;
pub type FnRtlTryAcquireSRWLockExclusive = unsafe extern "system" fn(PRTL_SRWLOCK) -> BOOLEAN;
pub type FnRtlTryAcquireSRWLockShared = unsafe extern "system" fn(PRTL_SRWLOCK) -> BOOLEAN;
pub type FnRtlTryEnterCriticalSection = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> LOGICAL;
pub type FnRtlUTF8ToUnicodeN =
    unsafe extern "system" fn(PWSTR, ULONG, PULONG, PCCH, ULONG) -> NTSTATUS;
pub type FnRtlUnhandledExceptionFilter = unsafe extern "system" fn(PEXCEPTION_POINTERS) -> LONG;
pub type FnRtlUnhandledExceptionFilter2 =
    unsafe extern "system" fn(PEXCEPTION_POINTERS, ULONG) -> LONG;
pub type FnRtlUnicodeStringToAnsiString =
    unsafe extern "system" fn(PANSI_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUnicodeStringToCountedOemString =
    unsafe extern "system" fn(POEM_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUnicodeStringToInteger =
    unsafe extern "system" fn(PCUNICODE_STRING, ULONG, PULONG) -> NTSTATUS;
pub type FnRtlUnicodeStringToOemString =
    unsafe extern "system" fn(POEM_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUnicodeToCustomCPN =
    unsafe extern "system" fn(PCPTABLEINFO, PCH, ULONG, PULONG, PWCH, ULONG) -> NTSTATUS;
pub type FnRtlUnicodeToMultiByteN =
    unsafe extern "system" fn(PCHAR, ULONG, PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUnicodeToMultiByteSize = unsafe extern "system" fn(PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUnicodeToOemN =
    unsafe extern "system" fn(PCHAR, ULONG, PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUnicodeToUTF8N =
    unsafe extern "system" fn(PCHAR, ULONG, PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUniform = unsafe extern "system" fn(PULONG) -> ULONG;
pub type FnRtlUnlockBootStatusData = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnRtlUnlockCurrentThread = unsafe extern "system" fn() -> NTSTATUS;
pub type FnRtlUnlockHeap = unsafe extern "system" fn(PVOID) -> BOOLEAN;
pub type FnRtlUnlockMemoryBlockLookaside = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlUnlockMemoryZone = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlUnlockModuleSection = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnRtlUnwind = unsafe extern "system" fn(PVOID, PVOID, PEXCEPTION_RECORD, PVOID) -> ();
pub type FnRtlUnwindEx = unsafe extern "system" fn(
    PVOID,
    PVOID,
    PEXCEPTION_RECORD,
    PVOID,
    PCONTEXT,
    PUNWIND_HISTORY_TABLE,
) -> ();
pub type FnRtlUpcaseUnicodeChar = unsafe extern "system" fn(WCHAR) -> WCHAR;
pub type FnRtlUpcaseUnicodeString =
    unsafe extern "system" fn(PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeStringToAnsiString =
    unsafe extern "system" fn(PANSI_STRING, PUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeStringToCountedOemString =
    unsafe extern "system" fn(POEM_STRING, PCUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeStringToOemString =
    unsafe extern "system" fn(POEM_STRING, PUNICODE_STRING, BOOLEAN) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeToCustomCPN =
    unsafe extern "system" fn(PCPTABLEINFO, PCH, ULONG, PULONG, PWCH, ULONG) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeToMultiByteN =
    unsafe extern "system" fn(PCHAR, ULONG, PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUpcaseUnicodeToOemN =
    unsafe extern "system" fn(PCHAR, ULONG, PULONG, PCWCH, ULONG) -> NTSTATUS;
pub type FnRtlUpdateClonedCriticalSection = unsafe extern "system" fn(PRTL_CRITICAL_SECTION) -> ();
pub type FnRtlUpdateClonedSRWLock = unsafe extern "system" fn(PRTL_SRWLOCK, LOGICAL) -> ();
pub type FnRtlUpdateTimer = unsafe extern "system" fn(HANDLE, HANDLE, ULONG, ULONG) -> NTSTATUS;
pub type FnRtlUpperChar = unsafe extern "system" fn(CHAR) -> CHAR;
pub type FnRtlUpperString = unsafe extern "system" fn(PSTRING, *const STRING) -> ();
pub type FnRtlUserThreadStart = unsafe extern "system" fn(PTHREAD_START_ROUTINE, PVOID) -> ();
pub type FnRtlValidAcl = unsafe extern "system" fn(PACL) -> BOOLEAN;
pub type FnRtlValidProcessProtection = unsafe extern "system" fn(PS_PROTECTION) -> BOOLEAN;
pub type FnRtlValidRelativeSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, ULONG, SECURITY_INFORMATION) -> BOOLEAN;
pub type FnRtlValidSecurityDescriptor = unsafe extern "system" fn(PSECURITY_DESCRIPTOR) -> BOOLEAN;
pub type FnRtlValidSid = unsafe extern "system" fn(PSID) -> BOOLEAN;
pub type FnRtlValidateHeap = unsafe extern "system" fn(PVOID, ULONG, PVOID) -> BOOLEAN;
pub type FnRtlValidateProcessHeaps = unsafe extern "system" fn() -> BOOLEAN;
pub type FnRtlValidateUnicodeString =
    unsafe extern "system" fn(ULONG, PCUNICODE_STRING) -> NTSTATUS;
pub type FnRtlVerifyVersionInfo =
    unsafe extern "system" fn(PRTL_OSVERSIONINFOEXW, ULONG, ULONGLONG) -> NTSTATUS;
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
pub type FnRtlWaitOnAddress =
    unsafe extern "system" fn(*mut VOID, PVOID, SIZE_T, PLARGE_INTEGER) -> NTSTATUS;
pub type FnRtlWakeAddressAll = unsafe extern "system" fn(PVOID) -> ();
pub type FnRtlWakeAddressSingle = unsafe extern "system" fn(PVOID) -> ();
pub type FnRtlWakeAllConditionVariable = unsafe extern "system" fn(PRTL_CONDITION_VARIABLE) -> ();
pub type FnRtlWakeConditionVariable = unsafe extern "system" fn(PRTL_CONDITION_VARIABLE) -> ();
pub type FnRtlWalkFrameChain = unsafe extern "system" fn(*mut PVOID, ULONG, ULONG) -> ULONG;
pub type FnRtlWalkHeap = unsafe extern "system" fn(PVOID, PRTL_HEAP_WALK_ENTRY) -> NTSTATUS;
pub type FnRtlWeaklyEnumerateEntryHashTable =
    unsafe extern "system" fn(
        PRTL_DYNAMIC_HASH_TABLE,
        PRTL_DYNAMIC_HASH_TABLE_ENUMERATOR,
    ) -> PRTL_DYNAMIC_HASH_TABLE_ENTRY;
pub type FnRtlWerpReportException =
    unsafe extern "system" fn(ULONG, HANDLE, ULONG, PHANDLE) -> NTSTATUS;
pub type FnRtlWow64EnableFsRedirection = unsafe extern "system" fn(BOOLEAN) -> NTSTATUS;
pub type FnRtlWow64EnableFsRedirectionEx = unsafe extern "system" fn(PVOID, *mut PVOID) -> NTSTATUS;
pub type FnRtlWow64GetThreadContext = unsafe extern "system" fn(HANDLE, PWOW64_CONTEXT) -> NTSTATUS;
pub type FnRtlWow64SetThreadContext = unsafe extern "system" fn(HANDLE, PWOW64_CONTEXT) -> NTSTATUS;
pub type FnRtlWriteRegistryValue =
    unsafe extern "system" fn(ULONG, PCWSTR, PCWSTR, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnRtlZeroHeap = unsafe extern "system" fn(PVOID, ULONG) -> NTSTATUS;
pub type FnRtlZeroMemory = unsafe extern "system" fn(*mut c_void, usize) -> ();
pub type FnTpAllocAlpcCompletion = unsafe extern "system" fn(
    *mut PTP_ALPC,
    HANDLE,
    PTP_ALPC_CALLBACK,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpAllocAlpcCompletionEx = unsafe extern "system" fn(
    *mut PTP_ALPC,
    HANDLE,
    PTP_ALPC_CALLBACK_EX,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpAllocCleanupGroup = unsafe extern "system" fn(*mut PTP_CLEANUP_GROUP) -> NTSTATUS;
pub type FnTpAllocIoCompletion = unsafe extern "system" fn(
    *mut PTP_IO,
    HANDLE,
    PTP_IO_CALLBACK,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpAllocPool = unsafe extern "system" fn(*mut PTP_POOL, PVOID) -> NTSTATUS;
pub type FnTpAllocTimer = unsafe extern "system" fn(
    *mut PTP_TIMER,
    PTP_TIMER_CALLBACK,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpAllocWait = unsafe extern "system" fn(
    *mut PTP_WAIT,
    PTP_WAIT_CALLBACK,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpAllocWork = unsafe extern "system" fn(
    *mut PTP_WORK,
    PTP_WORK_CALLBACK,
    PVOID,
    PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type FnTpCallbackLeaveCriticalSectionOnCompletion =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PRTL_CRITICAL_SECTION) -> ();
pub type FnTpCallbackMayRunLong = unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> NTSTATUS;
pub type FnTpCallbackReleaseMutexOnCompletion =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE) -> ();
pub type FnTpCallbackReleaseSemaphoreOnCompletion =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE, LONG) -> ();
pub type FnTpCallbackSetEventOnCompletion =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, HANDLE) -> ();
pub type FnTpCallbackUnloadDllOnCompletion =
    unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID) -> ();
pub type FnTpCancelAsyncIoOperation = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnTpCaptureCaller = unsafe extern "system" fn(TP_TRACE_TYPE) -> ();
pub type FnTpCheckTerminateWorker = unsafe extern "system" fn(HANDLE) -> ();
pub type FnTpDisassociateCallback = unsafe extern "system" fn(PTP_CALLBACK_INSTANCE) -> ();
pub type FnTpIsTimerSet = unsafe extern "system" fn(PTP_TIMER) -> LOGICAL;
pub type FnTpPostWork = unsafe extern "system" fn(PTP_WORK) -> ();
pub type FnTpQueryPoolStackInformation =
    unsafe extern "system" fn(PTP_POOL, PTP_POOL_STACK_INFORMATION) -> NTSTATUS;
pub type FnTpReleaseAlpcCompletion = unsafe extern "system" fn(PTP_ALPC) -> ();
pub type FnTpReleaseCleanupGroup = unsafe extern "system" fn(PTP_CLEANUP_GROUP) -> ();
pub type FnTpReleaseCleanupGroupMembers =
    unsafe extern "system" fn(PTP_CLEANUP_GROUP, LOGICAL, PVOID) -> ();
pub type FnTpReleaseIoCompletion = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnTpReleasePool = unsafe extern "system" fn(PTP_POOL) -> ();
pub type FnTpReleaseTimer = unsafe extern "system" fn(PTP_TIMER) -> ();
pub type FnTpReleaseWait = unsafe extern "system" fn(PTP_WAIT) -> ();
pub type FnTpReleaseWork = unsafe extern "system" fn(PTP_WORK) -> ();
pub type FnTpSetPoolMaxThreads = unsafe extern "system" fn(PTP_POOL, LONG) -> ();
pub type FnTpSetPoolMinThreads = unsafe extern "system" fn(PTP_POOL, LONG) -> NTSTATUS;
pub type FnTpSetPoolStackInformation =
    unsafe extern "system" fn(PTP_POOL, PTP_POOL_STACK_INFORMATION) -> NTSTATUS;
pub type FnTpSetTimer = unsafe extern "system" fn(PTP_TIMER, PLARGE_INTEGER, LONG, LONG) -> ();
pub type FnTpSetWait = unsafe extern "system" fn(PTP_WAIT, HANDLE, PLARGE_INTEGER) -> ();
pub type FnTpSimpleTryPost =
    unsafe extern "system" fn(PTP_SIMPLE_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> NTSTATUS;
pub type FnTpStartAsyncIoOperation = unsafe extern "system" fn(PTP_IO) -> ();
pub type FnTpWaitForAlpcCompletion = unsafe extern "system" fn(PTP_ALPC) -> ();
pub type FnTpWaitForIoCompletion = unsafe extern "system" fn(PTP_IO, LOGICAL) -> ();
pub type FnTpWaitForTimer = unsafe extern "system" fn(PTP_TIMER, LOGICAL) -> ();
pub type FnTpWaitForWait = unsafe extern "system" fn(PTP_WAIT, LOGICAL) -> ();
pub type FnTpWaitForWork = unsafe extern "system" fn(PTP_WORK, LOGICAL) -> ();
pub type FnVerSetConditionMask = unsafe extern "system" fn(ULONGLONG, DWORD, BYTE) -> ULONGLONG;
pub type FnZwAcceptConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PVOID,
    PPORT_MESSAGE,
    BOOLEAN,
    PPORT_VIEW,
    PREMOTE_PORT_VIEW,
) -> NTSTATUS;
pub type FnZwAccessCheck = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    HANDLE,
    ACCESS_MASK,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnZwAccessCheckAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    ACCESS_MASK,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwAccessCheckByType = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    ACCESS_MASK,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnZwAccessCheckByTypeAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    PSID,
    ACCESS_MASK,
    AUDIT_EVENT_TYPE,
    ULONG,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwAccessCheckByTypeResultList = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSID,
    HANDLE,
    ACCESS_MASK,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    PPRIVILEGE_SET,
    PULONG,
    PACCESS_MASK,
    PNTSTATUS,
) -> NTSTATUS;
pub type FnZwAccessCheckByTypeResultListAndAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    PSID,
    ACCESS_MASK,
    AUDIT_EVENT_TYPE,
    ULONG,
    POBJECT_TYPE_LIST,
    ULONG,
    PGENERIC_MAPPING,
    BOOLEAN,
    PACCESS_MASK,
    PNTSTATUS,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwAccessCheckByTypeResultListAndAuditAlarmByHandle =
    unsafe extern "system" fn(
        PUNICODE_STRING,
        PVOID,
        HANDLE,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PSECURITY_DESCRIPTOR,
        PSID,
        ACCESS_MASK,
        AUDIT_EVENT_TYPE,
        ULONG,
        POBJECT_TYPE_LIST,
        ULONG,
        PGENERIC_MAPPING,
        BOOLEAN,
        PACCESS_MASK,
        PNTSTATUS,
        PBOOLEAN,
    ) -> NTSTATUS;
pub type FnZwAddAtom = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM) -> NTSTATUS;
pub type FnZwAddAtomEx = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM, ULONG) -> NTSTATUS;
pub type FnZwAddBootEntry = unsafe extern "system" fn(PBOOT_ENTRY, PULONG) -> NTSTATUS;
pub type FnZwAddDriverEntry = unsafe extern "system" fn(PEFI_DRIVER_ENTRY, PULONG) -> NTSTATUS;
pub type FnZwAdjustGroupsToken = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    PTOKEN_GROUPS,
    ULONG,
    PTOKEN_GROUPS,
    PULONG,
) -> NTSTATUS;
pub type FnZwAdjustPrivilegesToken = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    PTOKEN_PRIVILEGES,
    ULONG,
    PTOKEN_PRIVILEGES,
    PULONG,
) -> NTSTATUS;
pub type FnZwAdjustTokenClaimsAndDeviceGroups = unsafe extern "system" fn(
    HANDLE,
    BOOLEAN,
    BOOLEAN,
    BOOLEAN,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    ULONG,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    ULONG,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    ULONG,
    PTOKEN_GROUPS,
    PULONG,
    PULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwAlertResumeThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnZwAlertThread = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwAlertThreadByThreadId = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwAllocateLocallyUniqueId = unsafe extern "system" fn(PLUID) -> NTSTATUS;
pub type FnZwAllocateReserveObject =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, MEMORY_RESERVE_TYPE) -> NTSTATUS;
pub type FnZwAllocateUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnZwAllocateUuids =
    unsafe extern "system" fn(PULARGE_INTEGER, PULONG, PULONG, PCHAR) -> NTSTATUS;
pub type FnZwAllocateVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG) -> NTSTATUS;
pub type FnZwAlpcAcceptConnectPort = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    PVOID,
    PPORT_MESSAGE,
    PALPC_MESSAGE_ATTRIBUTES,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwAlpcCancelMessage =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_CONTEXT_ATTR) -> NTSTATUS;
pub type FnZwAlpcConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    ULONG,
    PSID,
    PPORT_MESSAGE,
    PULONG,
    PALPC_MESSAGE_ATTRIBUTES,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwAlpcConnectPortEx = unsafe extern "system" fn(
    PHANDLE,
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    PALPC_PORT_ATTRIBUTES,
    ULONG,
    PSECURITY_DESCRIPTOR,
    PPORT_MESSAGE,
    PSIZE_T,
    PALPC_MESSAGE_ATTRIBUTES,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwAlpcCreatePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwAlpcCreatePortSection =
    unsafe extern "system" fn(HANDLE, ULONG, HANDLE, SIZE_T, PALPC_HANDLE, PSIZE_T) -> NTSTATUS;
pub type FnZwAlpcCreateResourceReserve =
    unsafe extern "system" fn(HANDLE, ULONG, SIZE_T, PALPC_HANDLE) -> NTSTATUS;
pub type FnZwAlpcCreateSectionView =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_DATA_VIEW_ATTR) -> NTSTATUS;
pub type FnZwAlpcCreateSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, PALPC_SECURITY_ATTR) -> NTSTATUS;
pub type FnZwAlpcDeletePortSection =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnZwAlpcDeleteResourceReserve =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnZwAlpcDeleteSectionView = unsafe extern "system" fn(HANDLE, ULONG, PVOID) -> NTSTATUS;
pub type FnZwAlpcDeleteSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnZwAlpcDisconnectPort = unsafe extern "system" fn(HANDLE, ULONG) -> NTSTATUS;
pub type FnZwAlpcImpersonateClientContainerOfPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG) -> NTSTATUS;
pub type FnZwAlpcImpersonateClientOfPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, PVOID) -> NTSTATUS;
pub type FnZwAlpcOpenSenderProcess = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PPORT_MESSAGE,
    ULONG,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
) -> NTSTATUS;
pub type FnZwAlpcOpenSenderThread = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PPORT_MESSAGE,
    ULONG,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
) -> NTSTATUS;
pub type FnZwAlpcQueryInformation = unsafe extern "system" fn(
    HANDLE,
    ALPC_PORT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwAlpcQueryInformationMessage = unsafe extern "system" fn(
    HANDLE,
    PPORT_MESSAGE,
    ALPC_MESSAGE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwAlpcRevokeSecurityContext =
    unsafe extern "system" fn(HANDLE, ULONG, ALPC_HANDLE) -> NTSTATUS;
pub type FnZwAlpcSendWaitReceivePort = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PPORT_MESSAGE,
    PALPC_MESSAGE_ATTRIBUTES,
    PPORT_MESSAGE,
    PSIZE_T,
    PALPC_MESSAGE_ATTRIBUTES,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwAlpcSetInformation =
    unsafe extern "system" fn(HANDLE, ALPC_PORT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwAreMappedFilesTheSame = unsafe extern "system" fn(PVOID, PVOID) -> NTSTATUS;
pub type FnZwAssignProcessToJobObject = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwAssociateWaitCompletionPacket = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    HANDLE,
    PVOID,
    PVOID,
    NTSTATUS,
    ULONG_PTR,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwCallbackReturn = unsafe extern "system" fn(PVOID, ULONG, NTSTATUS) -> NTSTATUS;
pub type FnZwCancelIoFile = unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnZwCancelIoFileEx =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnZwCancelSynchronousIoFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnZwCancelTimer = unsafe extern "system" fn(HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnZwCancelTimer2 = unsafe extern "system" fn(HANDLE, PT2_CANCEL_PARAMETERS) -> NTSTATUS;
pub type FnZwCancelWaitCompletionPacket = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnZwClearEvent = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwCloseObjectAuditAlarm =
    unsafe extern "system" fn(PUNICODE_STRING, PVOID, BOOLEAN) -> NTSTATUS;
pub type FnZwCommitComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwCommitEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwCommitTransaction = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnZwCompactKeys = unsafe extern "system" fn(ULONG, *mut HANDLE) -> NTSTATUS;
pub type FnZwCompareObjects = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwCompareTokens = unsafe extern "system" fn(HANDLE, HANDLE, PBOOLEAN) -> NTSTATUS;
pub type FnZwCompleteConnectPort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwCompressKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    PSECURITY_QUALITY_OF_SERVICE,
    PPORT_VIEW,
    PREMOTE_PORT_VIEW,
    PULONG,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnZwContinue = unsafe extern "system" fn(PCONTEXT, BOOLEAN) -> NTSTATUS;
pub type FnZwCreateDebugObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwCreateDirectoryObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwCreateDirectoryObjectEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG) -> NTSTATUS;
pub type FnZwCreateEnlistment = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    HANDLE,
    HANDLE,
    POBJECT_ATTRIBUTES,
    ULONG,
    NOTIFICATION_MASK,
    PVOID,
) -> NTSTATUS;
pub type FnZwCreateEvent = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    EVENT_TYPE,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwCreateEventPair =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwCreateFile = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwCreateIRTimer = unsafe extern "system" fn(PHANDLE, ACCESS_MASK) -> NTSTATUS;
pub type FnZwCreateIoCompletion =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwCreateJobObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwCreateJobSet = unsafe extern "system" fn(ULONG, PJOB_SET_ARRAY, ULONG) -> NTSTATUS;
pub type FnZwCreateKey = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwCreateKeyTransacted = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    HANDLE,
    PULONG,
) -> NTSTATUS;
pub type FnZwCreateKeyedEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwCreateLowBoxToken = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PSID,
    ULONG,
    PSID_AND_ATTRIBUTES,
    ULONG,
    *mut HANDLE,
) -> NTSTATUS;
pub type FnZwCreateMailslotFile = unsafe extern "system" fn(
    PHANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwCreateMutant =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN) -> NTSTATUS;
pub type FnZwCreateNamedPipeFile = unsafe extern "system" fn(
    PHANDLE,
    ULONG,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwCreatePagingFile =
    unsafe extern "system" fn(PUNICODE_STRING, PLARGE_INTEGER, PLARGE_INTEGER, ULONG) -> NTSTATUS;
pub type FnZwCreatePartition =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwCreatePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnZwCreatePrivateNamespace =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID) -> NTSTATUS;
pub type FnZwCreateProcess = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    BOOLEAN,
    HANDLE,
    HANDLE,
    HANDLE,
) -> NTSTATUS;
pub type FnZwCreateProcessEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    ULONG,
    HANDLE,
    HANDLE,
    HANDLE,
    ULONG,
) -> NTSTATUS;
pub type FnZwCreateProfile = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PVOID,
    SIZE_T,
    ULONG,
    PULONG,
    ULONG,
    KPROFILE_SOURCE,
    KAFFINITY,
) -> NTSTATUS;
pub type FnZwCreateProfileEx = unsafe extern "system" fn(
    PHANDLE,
    HANDLE,
    PVOID,
    SIZE_T,
    ULONG,
    PULONG,
    ULONG,
    KPROFILE_SOURCE,
    USHORT,
    PGROUP_AFFINITY,
) -> NTSTATUS;
pub type FnZwCreateResourceManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    HANDLE,
    LPGUID,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnZwCreateSection = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE,
) -> NTSTATUS;
pub type FnZwCreateSemaphore =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG) -> NTSTATUS;
pub type FnZwCreateSymbolicLinkObject = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnZwCreateThread = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PCLIENT_ID,
    PCONTEXT,
    PINITIAL_TEB,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwCreateThreadEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;
pub type FnZwCreateTimer =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE) -> NTSTATUS;
pub type FnZwCreateTimer2 =
    unsafe extern "system" fn(PHANDLE, PVOID, PVOID, ULONG, ACCESS_MASK) -> NTSTATUS;
pub type FnZwCreateToken = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    TOKEN_TYPE,
    PLUID,
    PLARGE_INTEGER,
    PTOKEN_USER,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL,
    PTOKEN_SOURCE,
) -> NTSTATUS;
pub type FnZwCreateTokenEx = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    TOKEN_TYPE,
    PLUID,
    PLARGE_INTEGER,
    PTOKEN_USER,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    PTOKEN_MANDATORY_POLICY,
    PTOKEN_OWNER,
    PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL,
    PTOKEN_SOURCE,
) -> NTSTATUS;
pub type FnZwCreateTransaction = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    LPGUID,
    HANDLE,
    ULONG,
    ULONG,
    ULONG,
    PLARGE_INTEGER,
    PUNICODE_STRING,
) -> NTSTATUS;
pub type FnZwCreateTransactionManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnZwCreateUserProcess = unsafe extern "system" fn(
    PHANDLE,
    PHANDLE,
    ACCESS_MASK,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    ULONG,
    ULONG,
    PVOID,
    PPS_CREATE_INFO,
    PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;
pub type FnZwCreateWaitCompletionPacket =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwCreateWaitablePort =
    unsafe extern "system" fn(PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnZwCreateWnfStateName = unsafe extern "system" fn(
    PWNF_STATE_NAME,
    WNF_STATE_NAME_LIFETIME,
    WNF_DATA_SCOPE,
    BOOLEAN,
    PCWNF_TYPE_ID,
    ULONG,
    PSECURITY_DESCRIPTOR,
) -> NTSTATUS;
pub type FnZwCreateWorkerFactory = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
) -> NTSTATUS;
pub type FnZwDebugActiveProcess = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwDebugContinue = unsafe extern "system" fn(HANDLE, PCLIENT_ID, NTSTATUS) -> NTSTATUS;
pub type FnZwDelayExecution = unsafe extern "system" fn(BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwDeleteAtom = unsafe extern "system" fn(RTL_ATOM) -> NTSTATUS;
pub type FnZwDeleteBootEntry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnZwDeleteDriverEntry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnZwDeleteFile = unsafe extern "system" fn(POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwDeleteKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwDeleteObjectAuditAlarm =
    unsafe extern "system" fn(PUNICODE_STRING, PVOID, BOOLEAN) -> NTSTATUS;
pub type FnZwDeletePrivateNamespace = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwDeleteValueKey = unsafe extern "system" fn(HANDLE, PUNICODE_STRING) -> NTSTATUS;
pub type FnZwDeleteWnfStateData =
    unsafe extern "system" fn(PCWNF_STATE_NAME, *const VOID) -> NTSTATUS;
pub type FnZwDeleteWnfStateName = unsafe extern "system" fn(PCWNF_STATE_NAME) -> NTSTATUS;
pub type FnZwDeviceIoControlFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwDisableLastKnownGood = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwDisplayString = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnZwDrawText = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnZwDuplicateObject = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    HANDLE,
    PHANDLE,
    ACCESS_MASK,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnZwDuplicateToken = unsafe extern "system" fn(
    HANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    BOOLEAN,
    TOKEN_TYPE,
    PHANDLE,
) -> NTSTATUS;
pub type FnZwEnableLastKnownGood = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwEnumerateBootEntries = unsafe extern "system" fn(PVOID, PULONG) -> NTSTATUS;
pub type FnZwEnumerateDriverEntries = unsafe extern "system" fn(PVOID, PULONG) -> NTSTATUS;
pub type FnZwEnumerateKey = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    KEY_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwEnumerateSystemEnvironmentValuesEx =
    unsafe extern "system" fn(ULONG, PVOID, PULONG) -> NTSTATUS;
pub type FnZwEnumerateTransactionObject =
    unsafe extern "system" fn(HANDLE, KTMOBJECT_TYPE, PKTMOBJECT_CURSOR, ULONG, PULONG) -> NTSTATUS;
pub type FnZwEnumerateValueKey = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    KEY_VALUE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwExtendSection = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwFilterToken = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_GROUPS,
    PHANDLE,
) -> NTSTATUS;
pub type FnZwFilterTokenEx = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,
    PTOKEN_GROUPS,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    PUNICODE_STRING,
    PTOKEN_GROUPS,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION,
    PTOKEN_GROUPS,
    PHANDLE,
) -> NTSTATUS;
pub type FnZwFindAtom = unsafe extern "system" fn(PWSTR, ULONG, PRTL_ATOM) -> NTSTATUS;
pub type FnZwFlushBuffersFile = unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnZwFlushBuffersFileEx =
    unsafe extern "system" fn(HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK) -> NTSTATUS;
pub type FnZwFlushInstallUILanguage = unsafe extern "system" fn(LANGID, ULONG) -> NTSTATUS;
pub type FnZwFlushInstructionCache = unsafe extern "system" fn(HANDLE, PVOID, SIZE_T) -> NTSTATUS;
pub type FnZwFlushKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwFlushProcessWriteBuffers = unsafe extern "system" fn() -> ();
pub type FnZwFlushWriteBuffer = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwFreeUserPhysicalPages =
    unsafe extern "system" fn(HANDLE, PULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnZwFreeVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnZwFreezeRegistry = unsafe extern "system" fn(ULONG) -> NTSTATUS;
pub type FnZwFreezeTransactions =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwFsControlFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwGetCachedSigningLevel = unsafe extern "system" fn(
    HANDLE,
    PULONG,
    PSE_SIGNING_LEVEL,
    PUCHAR,
    PULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwGetCompleteWnfStateSubscription = unsafe extern "system" fn(
    PWNF_STATE_NAME,
    *mut ULONG64,
    ULONG,
    ULONG,
    PWNF_DELIVERY_DESCRIPTOR,
    ULONG,
) -> NTSTATUS;
pub type FnZwGetContextThread = unsafe extern "system" fn(HANDLE, PCONTEXT) -> NTSTATUS;
pub type FnZwGetCurrentProcessorNumber = unsafe extern "system" fn() -> ULONG;
pub type FnZwGetDevicePowerState =
    unsafe extern "system" fn(HANDLE, PDEVICE_POWER_STATE) -> NTSTATUS;
pub type FnZwGetMUIRegistryInfo = unsafe extern "system" fn(ULONG, PULONG, PVOID) -> NTSTATUS;
pub type FnZwGetNextProcess =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE) -> NTSTATUS;
pub type FnZwGetNextThread =
    unsafe extern "system" fn(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE) -> NTSTATUS;
pub type FnZwGetNlsSectionPtr =
    unsafe extern "system" fn(ULONG, ULONG, PVOID, *mut PVOID, PULONG) -> NTSTATUS;
pub type FnZwGetNotificationResourceManager = unsafe extern "system" fn(
    HANDLE,
    PTRANSACTION_NOTIFICATION,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
    ULONG,
    ULONG_PTR,
) -> NTSTATUS;
pub type FnZwGetWriteWatch = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PVOID,
    SIZE_T,
    *mut PVOID,
    PULONG_PTR,
    PULONG,
) -> NTSTATUS;
pub type FnZwImpersonateAnonymousToken = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwImpersonateClientOfPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwImpersonateThread =
    unsafe extern "system" fn(HANDLE, HANDLE, PSECURITY_QUALITY_OF_SERVICE) -> NTSTATUS;
pub type FnZwInitializeNlsFiles =
    unsafe extern "system" fn(*mut PVOID, PLCID, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwInitializeRegistry = unsafe extern "system" fn(USHORT) -> NTSTATUS;
pub type FnZwInitiatePowerAction =
    unsafe extern "system" fn(POWER_ACTION, SYSTEM_POWER_STATE, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnZwIsProcessInJob = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwIsSystemResumeAutomatic = unsafe extern "system" fn() -> BOOLEAN;
pub type FnZwIsUILanguageComitted = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwListenPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwLoadDriver = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnZwLoadKey =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwLoadKey2 =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwLoadKeyEx = unsafe extern "system" fn(
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    ULONG,
    HANDLE,
    HANDLE,
    ACCESS_MASK,
    PHANDLE,
    PIO_STATUS_BLOCK,
) -> NTSTATUS;
pub type FnZwLockFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    ULONG,
    BOOLEAN,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwLockProductActivationKeys =
    unsafe extern "system" fn(*mut ULONG, *mut ULONG) -> NTSTATUS;
pub type FnZwLockRegistryKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwLockVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnZwMakePermanentObject = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwMakeTemporaryObject = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwManagePartition =
    unsafe extern "system" fn(MEMORY_PARTITION_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwMapCMFModule =
    unsafe extern "system" fn(ULONG, ULONG, PULONG, PULONG, PULONG, *mut PVOID) -> NTSTATUS;
pub type FnZwMapUserPhysicalPages =
    unsafe extern "system" fn(PVOID, ULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnZwMapUserPhysicalPagesScatter =
    unsafe extern "system" fn(*mut PVOID, ULONG_PTR, PULONG_PTR) -> NTSTATUS;
pub type FnZwMapViewOfSection = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut PVOID,
    ULONG_PTR,
    SIZE_T,
    PLARGE_INTEGER,
    PSIZE_T,
    SECTION_INHERIT,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnZwModifyBootEntry = unsafe extern "system" fn(PBOOT_ENTRY) -> NTSTATUS;
pub type FnZwModifyDriverEntry = unsafe extern "system" fn(PEFI_DRIVER_ENTRY) -> NTSTATUS;
pub type FnZwNotifyChangeDirectoryFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwNotifyChangeKey = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwNotifyChangeMultipleKeys = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    *mut OBJECT_ATTRIBUTES,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwNotifyChangeSession = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    PLARGE_INTEGER,
    IO_SESSION_EVENT,
    IO_SESSION_STATE,
    IO_SESSION_STATE,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwOpenDirectoryObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenEnlistment =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenEventPair =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenFile = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG,
) -> NTSTATUS;
pub type FnZwOpenIoCompletion =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenJobObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenKey =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenKeyEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwOpenKeyTransacted =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE) -> NTSTATUS;
pub type FnZwOpenKeyTransactedEx =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE) -> NTSTATUS;
pub type FnZwOpenKeyedEvent =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenMutant =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenObjectAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    ACCESS_MASK,
    ACCESS_MASK,
    PPRIVILEGE_SET,
    BOOLEAN,
    BOOLEAN,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwOpenPartition =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenPrivateNamespace =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID) -> NTSTATUS;
pub type FnZwOpenProcess =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) -> NTSTATUS;
pub type FnZwOpenProcessToken = unsafe extern "system" fn(HANDLE, ACCESS_MASK, PHANDLE) -> NTSTATUS;
pub type FnZwOpenProcessTokenEx =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, ULONG, PHANDLE) -> NTSTATUS;
pub type FnZwOpenResourceManager =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenSection =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenSemaphore =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenSession =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenSymbolicLinkObject =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenThread =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) -> NTSTATUS;
pub type FnZwOpenThreadToken =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE) -> NTSTATUS;
pub type FnZwOpenThreadTokenEx =
    unsafe extern "system" fn(HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE) -> NTSTATUS;
pub type FnZwOpenTimer =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwOpenTransaction =
    unsafe extern "system" fn(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE) -> NTSTATUS;
pub type FnZwOpenTransactionManager = unsafe extern "system" fn(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PUNICODE_STRING,
    LPGUID,
    ULONG,
) -> NTSTATUS;
pub type FnZwPlugPlayControl =
    unsafe extern "system" fn(PLUGPLAY_CONTROL_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwPowerInformation =
    unsafe extern "system" fn(POWER_INFORMATION_LEVEL, PVOID, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnZwPrePrepareComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwPrePrepareEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwPrepareComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwPrepareEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwPrivilegeCheck =
    unsafe extern "system" fn(HANDLE, PPRIVILEGE_SET, PBOOLEAN) -> NTSTATUS;
pub type FnZwPrivilegeObjectAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PVOID,
    HANDLE,
    ACCESS_MASK,
    PPRIVILEGE_SET,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwPrivilegedServiceAuditAlarm = unsafe extern "system" fn(
    PUNICODE_STRING,
    PUNICODE_STRING,
    HANDLE,
    PPRIVILEGE_SET,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwPropagationComplete =
    unsafe extern "system" fn(HANDLE, ULONG, ULONG, PVOID) -> NTSTATUS;
pub type FnZwPropagationFailed = unsafe extern "system" fn(HANDLE, ULONG, NTSTATUS) -> NTSTATUS;
pub type FnZwProtectVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG, PULONG) -> NTSTATUS;
pub type FnZwPulseEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnZwQueryAttributesFile =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION) -> NTSTATUS;
pub type FnZwQueryBootEntryOrder = unsafe extern "system" fn(PULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryBootOptions = unsafe extern "system" fn(PBOOT_OPTIONS, PULONG) -> NTSTATUS;
pub type FnZwQueryDebugFilterState = unsafe extern "system" fn(ULONG, ULONG) -> NTSTATUS;
pub type FnZwQueryDefaultLocale = unsafe extern "system" fn(BOOLEAN, PLCID) -> NTSTATUS;
pub type FnZwQueryDefaultUILanguage = unsafe extern "system" fn(*mut LANGID) -> NTSTATUS;
pub type FnZwQueryDirectoryFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
    BOOLEAN,
    PUNICODE_STRING,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwQueryDirectoryObject =
    unsafe extern "system" fn(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryDriverEntryOrder = unsafe extern "system" fn(PULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryEaFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    PULONG,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwQueryEvent =
    unsafe extern "system" fn(HANDLE, EVENT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryFullAttributesFile =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, PFILE_NETWORK_OPEN_INFORMATION) -> NTSTATUS;
pub type FnZwQueryInformationAtom =
    unsafe extern "system" fn(RTL_ATOM, ATOM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationEnlistment = unsafe extern "system" fn(
    HANDLE,
    ENLISTMENT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnZwQueryInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationPort =
    unsafe extern "system" fn(HANDLE, PORT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationProcess =
    unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationResourceManager = unsafe extern "system" fn(
    HANDLE,
    RESOURCEMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryInformationThread =
    unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationToken =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInformationTransaction = unsafe extern "system" fn(
    HANDLE,
    TRANSACTION_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryInformationTransactionManager = unsafe extern "system" fn(
    HANDLE,
    TRANSACTIONMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryInformationWorkerFactory =
    unsafe extern "system" fn(HANDLE, WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryInstallUILanguage = unsafe extern "system" fn(*mut LANGID) -> NTSTATUS;
pub type FnZwQueryIntervalProfile = unsafe extern "system" fn(KPROFILE_SOURCE, PULONG) -> NTSTATUS;
pub type FnZwQueryIoCompletion = unsafe extern "system" fn(
    HANDLE,
    IO_COMPLETION_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryKey =
    unsafe extern "system" fn(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryLicenseValue =
    unsafe extern "system" fn(PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryMultipleValueKey =
    unsafe extern "system" fn(HANDLE, PKEY_VALUE_ENTRY, ULONG, PVOID, PULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryMutant =
    unsafe extern "system" fn(HANDLE, MUTANT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryObject =
    unsafe extern "system" fn(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryOpenSubKeys = unsafe extern "system" fn(POBJECT_ATTRIBUTES, PULONG) -> NTSTATUS;
pub type FnZwQueryOpenSubKeysEx =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG) -> NTSTATUS;
pub type FnZwQueryPerformanceCounter =
    unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwQueryPortInformationProcess = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwQueryQuotaInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    BOOLEAN,
    PVOID,
    ULONG,
    PSID,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwQuerySection = unsafe extern "system" fn(
    HANDLE,
    SECTION_INFORMATION_CLASS,
    PVOID,
    SIZE_T,
    PSIZE_T,
) -> NTSTATUS;
pub type FnZwQuerySecurityAttributesToken =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQuerySecurityObject = unsafe extern "system" fn(
    HANDLE,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQuerySemaphore = unsafe extern "system" fn(
    HANDLE,
    SEMAPHORE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQuerySymbolicLinkObject =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnZwQuerySystemEnvironmentValue =
    unsafe extern "system" fn(PUNICODE_STRING, PWSTR, USHORT, PUSHORT) -> NTSTATUS;
pub type FnZwQuerySystemEnvironmentValueEx =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG) -> NTSTATUS;
pub type FnZwQuerySystemInformation =
    unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQuerySystemInformationEx = unsafe extern "system" fn(
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQuerySystemTime = unsafe extern "system" fn(PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwQueryTimer =
    unsafe extern "system" fn(HANDLE, TIMER_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryTimerResolution = unsafe extern "system" fn(PULONG, PULONG, PULONG) -> NTSTATUS;
pub type FnZwQueryValueKey = unsafe extern "system" fn(
    HANDLE,
    PUNICODE_STRING,
    KEY_VALUE_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    PVOID,
    MEMORY_INFORMATION_CLASS,
    PVOID,
    SIZE_T,
    PSIZE_T,
) -> NTSTATUS;
pub type FnZwQueryVolumeInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FS_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnZwQueryWnfStateData = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    PCWNF_TYPE_ID,
    *const VOID,
    PWNF_CHANGE_STAMP,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnZwQueryWnfStateNameInformation = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    WNF_STATE_NAME_INFORMATION,
    *const VOID,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwQueueApcThread =
    unsafe extern "system" fn(HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS;
pub type FnZwQueueApcThreadEx =
    unsafe extern "system" fn(HANDLE, HANDLE, PPS_APC_ROUTINE, PVOID, PVOID, PVOID) -> NTSTATUS;
pub type FnZwRaiseException =
    unsafe extern "system" fn(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN) -> NTSTATUS;
pub type FnZwRaiseHardError =
    unsafe extern "system" fn(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG) -> NTSTATUS;
pub type FnZwReadFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnZwReadFileScatter = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PFILE_SEGMENT_ELEMENT,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnZwReadOnlyEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwReadRequestData =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnZwReadVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnZwRecoverEnlistment = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub type FnZwRecoverResourceManager = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwRecoverTransactionManager = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwRegisterProtocolAddressInformation =
    unsafe extern "system" fn(HANDLE, PCRM_PROTOCOL_ID, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnZwRegisterThreadTerminatePort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwReleaseKeyedEvent =
    unsafe extern "system" fn(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwReleaseMutant = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnZwReleaseSemaphore = unsafe extern "system" fn(HANDLE, LONG, PLONG) -> NTSTATUS;
pub type FnZwReleaseWorkerFactoryWorker = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwRemoveIoCompletion = unsafe extern "system" fn(
    HANDLE,
    *mut PVOID,
    *mut PVOID,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwRemoveIoCompletionEx = unsafe extern "system" fn(
    HANDLE,
    PFILE_IO_COMPLETION_INFORMATION,
    ULONG,
    PULONG,
    PLARGE_INTEGER,
    BOOLEAN,
) -> NTSTATUS;
pub type FnZwRemoveProcessDebug = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwRenameKey = unsafe extern "system" fn(HANDLE, PUNICODE_STRING) -> NTSTATUS;
pub type FnZwRenameTransactionManager =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID) -> NTSTATUS;
pub type FnZwReplaceKey =
    unsafe extern "system" fn(POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwReplacePartitionUnit =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, ULONG) -> NTSTATUS;
pub type FnZwReplyPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwReplyWaitReceivePort =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PPORT_MESSAGE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwReplyWaitReceivePortEx = unsafe extern "system" fn(
    HANDLE,
    *mut PVOID,
    PPORT_MESSAGE,
    PPORT_MESSAGE,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnZwReplyWaitReplyPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwRequestPort = unsafe extern "system" fn(HANDLE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwRequestWaitReplyPort =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, PPORT_MESSAGE) -> NTSTATUS;
pub type FnZwResetEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnZwResetWriteWatch = unsafe extern "system" fn(HANDLE, PVOID, SIZE_T) -> NTSTATUS;
pub type FnZwRestoreKey = unsafe extern "system" fn(HANDLE, HANDLE, ULONG) -> NTSTATUS;
pub type FnZwResumeProcess = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwResumeThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnZwRevertContainerImpersonation = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwRollbackComplete = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwRollbackEnlistment = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwRollbackTransaction = unsafe extern "system" fn(HANDLE, BOOLEAN) -> NTSTATUS;
pub type FnZwRollforwardTransactionManager =
    unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwSaveKey = unsafe extern "system" fn(HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwSaveKeyEx = unsafe extern "system" fn(HANDLE, HANDLE, ULONG) -> NTSTATUS;
pub type FnZwSaveMergedKeys = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> NTSTATUS;
pub type FnZwSecureConnectPort = unsafe extern "system" fn(
    PHANDLE,
    PUNICODE_STRING,
    PSECURITY_QUALITY_OF_SERVICE,
    PPORT_VIEW,
    PSID,
    PREMOTE_PORT_VIEW,
    PULONG,
    PVOID,
    PULONG,
) -> NTSTATUS;
pub type FnZwSerializeBoot = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwSetBootEntryOrder = unsafe extern "system" fn(PULONG, ULONG) -> NTSTATUS;
pub type FnZwSetBootOptions = unsafe extern "system" fn(PBOOT_OPTIONS, ULONG) -> NTSTATUS;
pub type FnZwSetCachedSigningLevel =
    unsafe extern "system" fn(ULONG, SE_SIGNING_LEVEL, PHANDLE, ULONG, HANDLE) -> NTSTATUS;
pub type FnZwSetContextThread = unsafe extern "system" fn(HANDLE, PCONTEXT) -> NTSTATUS;
pub type FnZwSetDebugFilterState = unsafe extern "system" fn(ULONG, ULONG, BOOLEAN) -> NTSTATUS;
pub type FnZwSetDefaultHardErrorPort = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetDefaultLocale = unsafe extern "system" fn(BOOLEAN, LCID) -> NTSTATUS;
pub type FnZwSetDefaultUILanguage = unsafe extern "system" fn(LANGID) -> NTSTATUS;
pub type FnZwSetDriverEntryOrder = unsafe extern "system" fn(PULONG, ULONG) -> NTSTATUS;
pub type FnZwSetEaFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetEvent = unsafe extern "system" fn(HANDLE, PLONG) -> NTSTATUS;
pub type FnZwSetEventBoostPriority = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetHighWaitLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetIRTimer = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwSetInformationDebugObject =
    unsafe extern "system" fn(HANDLE, DEBUGOBJECTINFOCLASS, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwSetInformationEnlistment =
    unsafe extern "system" fn(HANDLE, ENLISTMENT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnZwSetInformationJobObject =
    unsafe extern "system" fn(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationKey =
    unsafe extern "system" fn(HANDLE, KEY_SET_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationObject =
    unsafe extern "system" fn(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationProcess =
    unsafe extern "system" fn(HANDLE, PROCESSINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationResourceManager =
    unsafe extern "system" fn(HANDLE, RESOURCEMANAGER_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationThread =
    unsafe extern "system" fn(HANDLE, THREADINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationToken =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationTransaction =
    unsafe extern "system" fn(HANDLE, TRANSACTION_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetInformationTransactionManager = unsafe extern "system" fn(
    HANDLE,
    TRANSACTIONMANAGER_INFORMATION_CLASS,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwSetInformationVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    VIRTUAL_MEMORY_INFORMATION_CLASS,
    ULONG_PTR,
    PMEMORY_RANGE_ENTRY,
    PVOID,
    ULONG,
) -> NTSTATUS;
pub type FnZwSetInformationWorkerFactory =
    unsafe extern "system" fn(HANDLE, WORKERFACTORYINFOCLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetIntervalProfile = unsafe extern "system" fn(ULONG, KPROFILE_SOURCE) -> NTSTATUS;
pub type FnZwSetIoCompletion =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR) -> NTSTATUS;
pub type FnZwSetIoCompletionEx =
    unsafe extern "system" fn(HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR) -> NTSTATUS;
pub type FnZwSetLdtEntries =
    unsafe extern "system" fn(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG) -> NTSTATUS;
pub type FnZwSetLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetLowWaitHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSetQuotaInformationFile =
    unsafe extern "system" fn(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetSecurityObject =
    unsafe extern "system" fn(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> NTSTATUS;
pub type FnZwSetSystemEnvironmentValue =
    unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING) -> NTSTATUS;
pub type FnZwSetSystemEnvironmentValueEx =
    unsafe extern "system" fn(PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG) -> NTSTATUS;
pub type FnZwSetSystemInformation =
    unsafe extern "system" fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetSystemPowerState =
    unsafe extern "system" fn(POWER_ACTION, SYSTEM_POWER_STATE, ULONG) -> NTSTATUS;
pub type FnZwSetSystemTime = unsafe extern "system" fn(PLARGE_INTEGER, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwSetThreadExecutionState =
    unsafe extern "system" fn(EXECUTION_STATE, *mut EXECUTION_STATE) -> NTSTATUS;
pub type FnZwSetTimer = unsafe extern "system" fn(
    HANDLE,
    PLARGE_INTEGER,
    PTIMER_APC_ROUTINE,
    PVOID,
    BOOLEAN,
    LONG,
    PBOOLEAN,
) -> NTSTATUS;
pub type FnZwSetTimer2 = unsafe extern "system" fn(
    HANDLE,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    PT2_SET_PARAMETERS,
) -> NTSTATUS;
pub type FnZwSetTimerEx =
    unsafe extern "system" fn(HANDLE, TIMER_SET_INFORMATION_CLASS, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetTimerResolution = unsafe extern "system" fn(ULONG, BOOLEAN, PULONG) -> NTSTATUS;
pub type FnZwSetUuidSeed = unsafe extern "system" fn(PCHAR) -> NTSTATUS;
pub type FnZwSetValueKey =
    unsafe extern "system" fn(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG) -> NTSTATUS;
pub type FnZwSetVolumeInformationFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FS_INFORMATION_CLASS,
) -> NTSTATUS;
pub type FnZwSetWnfProcessNotificationEvent = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwShutdownSystem = unsafe extern "system" fn(SHUTDOWN_ACTION) -> NTSTATUS;
pub type FnZwShutdownWorkerFactory = unsafe extern "system" fn(HANDLE, *mut LONG) -> NTSTATUS;
pub type FnZwSignalAndWaitForSingleObject =
    unsafe extern "system" fn(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwSinglePhaseReject = unsafe extern "system" fn(HANDLE, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwStartProfile = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwStopProfile = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSubscribeWnfStateChange =
    unsafe extern "system" fn(PCWNF_STATE_NAME, WNF_CHANGE_STAMP, ULONG, PULONG64) -> NTSTATUS;
pub type FnZwSuspendProcess = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwSuspendThread = unsafe extern "system" fn(HANDLE, PULONG) -> NTSTATUS;
pub type FnZwSystemDebugControl =
    unsafe extern "system" fn(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwTerminateJobObject = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnZwTerminateProcess = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnZwTerminateThread = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;
pub type FnZwTestAlert = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwThawRegistry = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwThawTransactions = unsafe extern "system" fn() -> NTSTATUS;
pub type FnZwTraceControl =
    unsafe extern "system" fn(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG) -> NTSTATUS;
pub type FnZwTraceEvent = unsafe extern "system" fn(HANDLE, ULONG, ULONG, PVOID) -> NTSTATUS;
pub type FnZwTranslateFilePath =
    unsafe extern "system" fn(PFILE_PATH, ULONG, PFILE_PATH, PULONG) -> NTSTATUS;
pub type FnZwUmsThreadYield = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnZwUnloadDriver = unsafe extern "system" fn(PUNICODE_STRING) -> NTSTATUS;
pub type FnZwUnloadKey = unsafe extern "system" fn(POBJECT_ATTRIBUTES) -> NTSTATUS;
pub type FnZwUnloadKey2 = unsafe extern "system" fn(POBJECT_ATTRIBUTES, ULONG) -> NTSTATUS;
pub type FnZwUnloadKeyEx = unsafe extern "system" fn(POBJECT_ATTRIBUTES, HANDLE) -> NTSTATUS;
pub type FnZwUnlockFile = unsafe extern "system" fn(
    HANDLE,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    PLARGE_INTEGER,
    ULONG,
) -> NTSTATUS;
pub type FnZwUnlockVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, PSIZE_T, ULONG) -> NTSTATUS;
pub type FnZwUnmapViewOfSection = unsafe extern "system" fn(HANDLE, PVOID) -> NTSTATUS;
pub type FnZwUnmapViewOfSectionEx = unsafe extern "system" fn(HANDLE, PVOID, ULONG) -> NTSTATUS;
pub type FnZwUnsubscribeWnfStateChange = unsafe extern "system" fn(PCWNF_STATE_NAME) -> NTSTATUS;
pub type FnZwUpdateWnfStateData = unsafe extern "system" fn(
    PCWNF_STATE_NAME,
    *const VOID,
    ULONG,
    PCWNF_TYPE_ID,
    *const VOID,
    WNF_CHANGE_STAMP,
    LOGICAL,
) -> NTSTATUS;
pub type FnZwVdmControl = unsafe extern "system" fn(VDMSERVICECLASS, PVOID) -> NTSTATUS;
pub type FnZwWaitForAlertByThreadId = unsafe extern "system" fn(PVOID, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwWaitForDebugEvent =
    unsafe extern "system" fn(HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID) -> NTSTATUS;
pub type FnZwWaitForKeyedEvent =
    unsafe extern "system" fn(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwWaitForMultipleObjects =
    unsafe extern "system" fn(ULONG, *mut HANDLE, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwWaitForMultipleObjects32 =
    unsafe extern "system" fn(ULONG, *mut LONG, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwWaitForSingleObject =
    unsafe extern "system" fn(HANDLE, BOOLEAN, PLARGE_INTEGER) -> NTSTATUS;
pub type FnZwWaitForWorkViaWorkerFactory =
    unsafe extern "system" fn(HANDLE, *mut FILE_IO_COMPLETION_INFORMATION) -> NTSTATUS;
pub type FnZwWaitHighEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwWaitLowEventPair = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwWorkerFactoryWorkerReady = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
pub type FnZwWriteFile = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnZwWriteFileGather = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PFILE_SEGMENT_ELEMENT,
    ULONG,
    PLARGE_INTEGER,
    PULONG,
) -> NTSTATUS;
pub type FnZwWriteRequestData =
    unsafe extern "system" fn(HANDLE, PPORT_MESSAGE, ULONG, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnZwWriteVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T) -> NTSTATUS;
pub type FnZwYieldExecution = unsafe extern "system" fn() -> NTSTATUS;
pub type FnvDbgPrintEx = unsafe extern "system" fn(ULONG, ULONG, PCCH, va_list) -> ULONG;
pub type FnvDbgPrintExWithPrefix =
    unsafe extern "system" fn(PCH, ULONG, ULONG, PCCH, va_list) -> ULONG;
