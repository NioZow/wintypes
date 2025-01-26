use ntapi::subprocesstag::TAG_INFO_LEVEL;
use winapi::shared::basetsd::{DWORD_PTR, ULONG64};
use winapi::shared::bcrypt::NTSTATUS;
use winapi::shared::evntprov::{
    EVENT_INFO_CLASS, PCEVENT_DESCRIPTOR, PENABLECALLBACK, PEVENT_DATA_DESCRIPTOR,
    PEVENT_FILTER_DESCRIPTOR, PREGHANDLE, REGHANDLE,
};
use winapi::shared::evntrace::{
    ETW_PROCESS_HANDLE_INFO_TYPE, PENABLE_TRACE_PARAMETERS, PEVENT_CALLBACK, PEVENT_INSTANCE_INFO,
    PEVENT_TRACE_HEADER, PEVENT_TRACE_LOGFILEA, PEVENT_TRACE_LOGFILEW, PEVENT_TRACE_PROPERTIES,
    PTRACEHANDLE, PTRACE_GUID_PROPERTIES, PTRACE_GUID_REGISTRATION, TRACEHANDLE, TRACE_INFO_CLASS,
    TRACE_QUERY_INFO_CLASS, WMIDPREQUEST,
};
use winapi::shared::guiddef::{GUID, LPCGUID, LPGUID};
use winapi::shared::minwindef::{
    BOOL, BYTE, DWORD, HKEY, LPBOOL, LPBYTE, LPCVOID, LPDWORD, LPFILETIME, LPVOID, PBOOL, PBYTE,
    PDWORD, PFILETIME, PHKEY, PUCHAR, PULONG, UCHAR, ULONG, USHORT, WORD,
};
use winapi::shared::ntdef::{
    BOOLEAN, HANDLE, LONG, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PBOOLEAN, PCSTR, PCWSTR, PHANDLE,
    PLARGE_INTEGER, PLONG, PLUID, PSHORT, PSTR, PVOID, PWSTR, ULONGLONG,
};
use winapi::um::accctrl::{
    ACCESS_MODE, MULTIPLE_TRUSTEE_OPERATION, PEXPLICIT_ACCESS_A, PEXPLICIT_ACCESS_W,
    PFN_OBJECT_MGR_FUNCTS, PINHERITED_FROMA, PINHERITED_FROMW, POBJECTS_AND_NAME_A,
    POBJECTS_AND_NAME_W, POBJECTS_AND_SID, PROG_INVOKE_SETTING, PTRUSTEE_A, PTRUSTEE_W,
    SE_OBJECT_TYPE, TRUSTEE_FORM, TRUSTEE_TYPE,
};
use winapi::um::aclapi::FN_PROGRESS;
use winapi::um::appmgmt::{APPCATEGORYINFOLIST, PINSTALLDATA, PMANAGEDAPPLICATION};
use winapi::um::lsalookup::{
    PLSA_OBJECT_ATTRIBUTES, PLSA_REFERENCED_DOMAIN_LIST, PLSA_TRANSLATED_NAME,
    PLSA_TRANSLATED_SID2, PLSA_TRUST_INFORMATION, PLSA_UNICODE_STRING,
};
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES, SECURITY_ATTRIBUTES};
use winapi::um::mschapp::{
    PENCRYPTED_LM_OWF_PASSWORD, PENCRYPTED_NT_OWF_PASSWORD, PLM_OWF_PASSWORD, PNT_OWF_PASSWORD,
    PSAMPR_ENCRYPTED_USER_PASSWORD,
};
use winapi::um::ncrypt::{HCRYPTHASH, HCRYPTKEY, HCRYPTPROV};
use winapi::um::ntlsa::{
    LSA_HANDLE, PCENTRAL_ACCESS_POLICY, PLSA_ENUMERATION_HANDLE,
    PLSA_FOREST_TRUST_COLLISION_INFORMATION, PLSA_FOREST_TRUST_INFORMATION, PLSA_REGISTRATION_INFO,
    PLSA_TRANSLATED_SID, POLICY_AUDIT_EVENT_TYPE, POLICY_DOMAIN_INFORMATION_CLASS,
    POLICY_INFORMATION_CLASS, PPOLICY_AUDIT_EVENT_TYPE, PTRUSTED_DOMAIN_AUTH_INFORMATION,
    PTRUSTED_DOMAIN_INFORMATION_EX, TRUSTED_INFORMATION_CLASS,
};
use winapi::um::ntsecapi::{
    PAUDIT_POLICY_INFORMATION, PCAUDIT_POLICY_INFORMATION, PLSA_HANDLE, PPOLICY_AUDIT_SID_ARRAY,
};
use winapi::um::perflib::{
    PerfRegInfoType, PERFLIBREQUEST, PPERF_COUNTERSET_INFO, PPERF_COUNTERSET_INSTANCE,
    PPERF_COUNTER_IDENTIFIER, PPERF_DATA_HEADER, PPERF_INSTANCE_HEADER, PPERF_PROVIDER_CONTEXT,
};
use winapi::um::processthreadsapi::{LPPROCESS_INFORMATION, LPSTARTUPINFOW};
use winapi::um::timezoneapi::PDYNAMIC_TIME_ZONE_INFORMATION;
use winapi::um::wct::{
    HWCT, PCOGETACTIVATIONSTATE, PCOGETCALLSTATE, PWAITCHAINCALLBACK, PWAITCHAIN_NODE_INFO,
};
use winapi::um::winbase::{LPHW_PROFILE_INFOA, LPHW_PROFILE_INFOW};
use winapi::um::wincred::{
    CRED_MARSHAL_TYPE, CRED_PROTECTION_TYPE, PCREDENTIALA, PCREDENTIALW,
    PCREDENTIAL_TARGET_INFORMATIONA, PCREDENTIAL_TARGET_INFORMATIONW, PCRED_MARSHAL_TYPE,
};
use winapi::um::wincrypt::ALG_ID;
use winapi::um::winefs::{
    PENCRYPTION_CERTIFICATE, PENCRYPTION_CERTIFICATE_HASH, PENCRYPTION_CERTIFICATE_HASH_LIST,
    PENCRYPTION_CERTIFICATE_LIST,
};
use winapi::um::winnt::{
    ACCESS_MASK, ACL_INFORMATION_CLASS, AUDIT_EVENT_TYPE, PACCESS_MASK, PACL, PGENERIC_MAPPING,
    PLUID_AND_ATTRIBUTES, POBJECT_TYPE_LIST, PPRIVILEGE_SET, PQUOTA_LIMITS, PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR_CONTROL, PSID, PSID_AND_ATTRIBUTES, PSID_IDENTIFIER_AUTHORITY,
    PSID_NAME_USE, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, SECURITY_DESCRIPTOR_CONTROL,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_INFORMATION, SID, TOKEN_INFORMATION_CLASS, TOKEN_TYPE,
    WELL_KNOWN_SID_TYPE,
};
use winapi::um::winreg::{LSTATUS, PVALENTA, PVALENTW, REGSAM};
use winapi::um::winsafer::{
    PSAFER_CODE_PROPERTIES, SAFER_LEVEL_HANDLE, SAFER_OBJECT_INFO_CLASS, SAFER_POLICY_INFO_CLASS,
};
use winapi::um::winsvc::{
    LPENUM_SERVICE_STATUSA, LPENUM_SERVICE_STATUSW, LPHANDLER_FUNCTION, LPHANDLER_FUNCTION_EX,
    LPQUERY_SERVICE_CONFIGA, LPQUERY_SERVICE_CONFIGW, LPQUERY_SERVICE_LOCK_STATUSA,
    LPQUERY_SERVICE_LOCK_STATUSW, LPSERVICE_STATUS, PSERVICE_NOTIFYA, PSERVICE_NOTIFYW,
    SC_ENUM_TYPE, SC_HANDLE, SC_LOCK, SC_STATUS_TYPE, SERVICE_STATUS_HANDLE, SERVICE_TABLE_ENTRYA,
    SERVICE_TABLE_ENTRYW,
};
use winapi::vc::vadefs::va_list;

pub type FnAbortSystemShutdownA = unsafe extern "system" fn(LPSTR) -> BOOL;
pub type FnAbortSystemShutdownW = unsafe extern "system" fn(LPWSTR) -> BOOL;
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
pub type FnAddMandatoryAce = unsafe extern "system" fn(PACL, DWORD, DWORD, DWORD, PSID) -> BOOL;
pub type FnAddUsersToEncryptedFile =
    unsafe extern "system" fn(LPCWSTR, PENCRYPTION_CERTIFICATE_LIST) -> DWORD;
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
pub type FnAreAllAccessesGranted = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnAreAnyAccessesGranted = unsafe extern "system" fn(DWORD, DWORD) -> BOOL;
pub type FnAuditComputeEffectivePolicyBySid = unsafe extern "system" fn(
    *const SID,
    *const GUID,
    ULONG,
    *mut PAUDIT_POLICY_INFORMATION,
) -> BOOLEAN;
pub type FnAuditComputeEffectivePolicyByToken = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    ULONG,
    *mut PAUDIT_POLICY_INFORMATION,
) -> BOOLEAN;
pub type FnAuditEnumerateCategories = unsafe extern "system" fn(PULONG) -> BOOLEAN;
pub type FnAuditEnumeratePerUserPolicy =
    unsafe extern "system" fn(*mut PPOLICY_AUDIT_SID_ARRAY) -> BOOLEAN;
pub type FnAuditEnumerateSubCategories =
    unsafe extern "system" fn(*const GUID, BOOLEAN, PULONG) -> BOOLEAN;
pub type FnAuditFree = unsafe extern "system" fn(PVOID) -> ();
pub type FnAuditLookupCategoryGuidFromCategoryId =
    unsafe extern "system" fn(POLICY_AUDIT_EVENT_TYPE, *mut GUID) -> BOOLEAN;
pub type FnAuditLookupCategoryIdFromCategoryGuid =
    unsafe extern "system" fn(*const GUID, PPOLICY_AUDIT_EVENT_TYPE) -> BOOLEAN;
pub type FnAuditLookupCategoryNameA = unsafe extern "system" fn(*const GUID, *mut PSTR) -> BOOLEAN;
pub type FnAuditLookupCategoryNameW = unsafe extern "system" fn(*const GUID, *mut PWSTR) -> BOOLEAN;
pub type FnAuditLookupSubCategoryNameA =
    unsafe extern "system" fn(*const GUID, *mut PSTR) -> BOOLEAN;
pub type FnAuditLookupSubCategoryNameW =
    unsafe extern "system" fn(*const GUID, *mut PWSTR) -> BOOLEAN;
pub type FnAuditQueryGlobalSaclA = unsafe extern "system" fn(PCSTR, *mut PACL) -> BOOLEAN;
pub type FnAuditQueryGlobalSaclW = unsafe extern "system" fn(PCWSTR, *mut PACL) -> BOOLEAN;
pub type FnAuditQueryPerUserPolicy = unsafe extern "system" fn(
    *const SID,
    *const GUID,
    ULONG,
    *mut PAUDIT_POLICY_INFORMATION,
) -> BOOLEAN;
pub type FnAuditQuerySecurity =
    unsafe extern "system" fn(SECURITY_INFORMATION, *mut PSECURITY_DESCRIPTOR) -> BOOLEAN;
pub type FnAuditQuerySystemPolicy =
    unsafe extern "system" fn(*const GUID, ULONG, *mut PAUDIT_POLICY_INFORMATION) -> BOOLEAN;
pub type FnAuditSetGlobalSaclA = unsafe extern "system" fn(PCSTR, PACL) -> BOOLEAN;
pub type FnAuditSetGlobalSaclW = unsafe extern "system" fn(PCWSTR, PACL) -> BOOLEAN;
pub type FnAuditSetPerUserPolicy =
    unsafe extern "system" fn(*const SID, PCAUDIT_POLICY_INFORMATION, ULONG) -> BOOLEAN;
pub type FnAuditSetSecurity =
    unsafe extern "system" fn(SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOLEAN;
pub type FnAuditSetSystemPolicy =
    unsafe extern "system" fn(PCAUDIT_POLICY_INFORMATION, ULONG) -> BOOLEAN;
pub type FnBuildExplicitAccessWithNameA =
    unsafe extern "system" fn(PEXPLICIT_ACCESS_A, LPSTR, DWORD, ACCESS_MODE, DWORD) -> ();
pub type FnBuildExplicitAccessWithNameW =
    unsafe extern "system" fn(PEXPLICIT_ACCESS_W, LPWSTR, DWORD, ACCESS_MODE, DWORD) -> ();
pub type FnBuildImpersonateExplicitAccessWithNameA = unsafe extern "system" fn(
    PEXPLICIT_ACCESS_A,
    LPSTR,
    PTRUSTEE_A,
    DWORD,
    ACCESS_MODE,
    DWORD,
) -> ();
pub type FnBuildImpersonateExplicitAccessWithNameW = unsafe extern "system" fn(
    PEXPLICIT_ACCESS_W,
    LPWSTR,
    PTRUSTEE_W,
    DWORD,
    ACCESS_MODE,
    DWORD,
) -> ();
pub type FnBuildImpersonateTrusteeA = unsafe extern "system" fn(PTRUSTEE_A, PTRUSTEE_A) -> ();
pub type FnBuildImpersonateTrusteeW = unsafe extern "system" fn(PTRUSTEE_W, PTRUSTEE_W) -> ();
pub type FnBuildSecurityDescriptorA = unsafe extern "system" fn(
    PTRUSTEE_A,
    PTRUSTEE_A,
    ULONG,
    PEXPLICIT_ACCESS_A,
    ULONG,
    PEXPLICIT_ACCESS_A,
    PSECURITY_DESCRIPTOR,
    PULONG,
    *mut PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnBuildSecurityDescriptorW = unsafe extern "system" fn(
    PTRUSTEE_W,
    PTRUSTEE_W,
    ULONG,
    PEXPLICIT_ACCESS_W,
    ULONG,
    PEXPLICIT_ACCESS_W,
    PSECURITY_DESCRIPTOR,
    PULONG,
    *mut PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnBuildTrusteeWithNameA = unsafe extern "system" fn(PTRUSTEE_A, LPSTR) -> ();
pub type FnBuildTrusteeWithNameW = unsafe extern "system" fn(PTRUSTEE_W, LPWSTR) -> ();
pub type FnBuildTrusteeWithObjectsAndNameA = unsafe extern "system" fn(
    PTRUSTEE_A,
    POBJECTS_AND_NAME_A,
    SE_OBJECT_TYPE,
    LPSTR,
    LPSTR,
    LPSTR,
) -> ();
pub type FnBuildTrusteeWithObjectsAndNameW = unsafe extern "system" fn(
    PTRUSTEE_W,
    POBJECTS_AND_NAME_W,
    SE_OBJECT_TYPE,
    LPWSTR,
    LPWSTR,
    LPWSTR,
) -> ();
pub type FnBuildTrusteeWithObjectsAndSidA =
    unsafe extern "system" fn(PTRUSTEE_A, POBJECTS_AND_SID, *mut GUID, *mut GUID, PSID) -> ();
pub type FnBuildTrusteeWithObjectsAndSidW =
    unsafe extern "system" fn(PTRUSTEE_W, POBJECTS_AND_SID, *mut GUID, *mut GUID, PSID) -> ();
pub type FnBuildTrusteeWithSidA = unsafe extern "system" fn(PTRUSTEE_A, PSID) -> ();
pub type FnBuildTrusteeWithSidW = unsafe extern "system" fn(PTRUSTEE_W, PSID) -> ();
pub type FnChangeServiceConfig2A = unsafe extern "system" fn(SC_HANDLE, DWORD, LPVOID) -> BOOL;
pub type FnChangeServiceConfig2W = unsafe extern "system" fn(SC_HANDLE, DWORD, LPVOID) -> BOOL;
pub type FnChangeServiceConfigA = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    DWORD,
    DWORD,
    LPCSTR,
    LPCSTR,
    LPDWORD,
    LPCSTR,
    LPCSTR,
    LPCSTR,
    LPCSTR,
) -> BOOL;
pub type FnChangeServiceConfigW = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    DWORD,
    DWORD,
    LPCWSTR,
    LPCWSTR,
    LPDWORD,
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
) -> BOOL;
pub type FnCheckForHiberboot = unsafe extern "system" fn(PBOOLEAN, BOOLEAN) -> DWORD;
pub type FnCheckTokenMembership = unsafe extern "system" fn(HANDLE, PSID, PBOOL) -> BOOL;
pub type FnCloseServiceHandle = unsafe extern "system" fn(SC_HANDLE) -> BOOL;
pub type FnCloseThreadWaitChainSession = unsafe extern "system" fn(HWCT) -> ();
pub type FnCloseTrace = unsafe extern "system" fn(TRACEHANDLE) -> ULONG;
pub type FnCommandLineFromMsiDescriptor =
    unsafe extern "system" fn(LPWSTR, LPWSTR, *mut DWORD) -> DWORD;
pub type FnControlService = unsafe extern "system" fn(SC_HANDLE, DWORD, LPSERVICE_STATUS) -> BOOL;
pub type FnControlServiceExA = unsafe extern "system" fn(SC_HANDLE, DWORD, DWORD, PVOID) -> BOOL;
pub type FnControlServiceExW = unsafe extern "system" fn(SC_HANDLE, DWORD, DWORD, PVOID) -> BOOL;
pub type FnControlTraceA =
    unsafe extern "system" fn(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES, ULONG) -> ULONG;
pub type FnControlTraceW =
    unsafe extern "system" fn(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES, ULONG) -> ULONG;
pub type FnConvertSecurityDescriptorToStringSecurityDescriptorA = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    DWORD,
    SECURITY_INFORMATION,
    *mut LPSTR,
    PULONG,
)
    -> BOOL;
pub type FnConvertSecurityDescriptorToStringSecurityDescriptorW = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    DWORD,
    SECURITY_INFORMATION,
    *mut LPWSTR,
    PULONG,
)
    -> BOOL;
pub type FnConvertSidToStringSidA = unsafe extern "system" fn(PSID, *mut LPSTR) -> BOOL;
pub type FnConvertSidToStringSidW = unsafe extern "system" fn(PSID, *mut LPWSTR) -> BOOL;
pub type FnConvertStringSecurityDescriptorToSecurityDescriptorA =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut PSECURITY_DESCRIPTOR, PULONG) -> BOOL;
pub type FnConvertStringSecurityDescriptorToSecurityDescriptorW =
    unsafe extern "system" fn(LPCWSTR, DWORD, *mut PSECURITY_DESCRIPTOR, PULONG) -> BOOL;
pub type FnConvertStringSidToSidA = unsafe extern "system" fn(LPCSTR, *mut PSID) -> BOOL;
pub type FnConvertStringSidToSidW = unsafe extern "system" fn(LPCWSTR, *mut PSID) -> BOOL;
pub type FnConvertToAutoInheritPrivateObjectSecurity = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    *mut PSECURITY_DESCRIPTOR,
    *mut GUID,
    BOOLEAN,
    PGENERIC_MAPPING,
) -> BOOL;
pub type FnCopySid = unsafe extern "system" fn(DWORD, PSID, PSID) -> BOOL;
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
pub type FnCreateProcessWithLogonW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
    DWORD,
    LPCWSTR,
    LPWSTR,
    DWORD,
    LPVOID,
    LPCWSTR,
    LPSTARTUPINFOW,
    LPPROCESS_INFORMATION,
) -> BOOL;
pub type FnCreateProcessWithTokenW = unsafe extern "system" fn(
    HANDLE,
    DWORD,
    LPCWSTR,
    LPWSTR,
    DWORD,
    LPVOID,
    LPCWSTR,
    LPSTARTUPINFOW,
    LPPROCESS_INFORMATION,
) -> BOOL;
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
pub type FnCreateServiceA = unsafe extern "system" fn(
    SC_HANDLE,
    LPCSTR,
    LPCSTR,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    LPCSTR,
    LPCSTR,
    LPDWORD,
    LPCSTR,
    LPCSTR,
    LPCSTR,
) -> SC_HANDLE;
pub type FnCreateServiceW = unsafe extern "system" fn(
    SC_HANDLE,
    LPCWSTR,
    LPCWSTR,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    LPCWSTR,
    LPCWSTR,
    LPDWORD,
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
) -> SC_HANDLE;
pub type FnCreateTraceInstanceId = unsafe extern "system" fn(HANDLE, PEVENT_INSTANCE_INFO) -> ULONG;
pub type FnCreateWellKnownSid =
    unsafe extern "system" fn(WELL_KNOWN_SID_TYPE, PSID, PSID, *mut DWORD) -> BOOL;
pub type FnCredDeleteA = unsafe extern "system" fn(LPCSTR, DWORD, DWORD) -> BOOL;
pub type FnCredDeleteW = unsafe extern "system" fn(LPCWSTR, DWORD, DWORD) -> BOOL;
pub type FnCredEnumerateA = unsafe extern "system" fn(LPCSTR, DWORD, *mut DWORD) -> BOOL;
pub type FnCredEnumerateW = unsafe extern "system" fn(LPCWSTR, DWORD, *mut DWORD) -> BOOL;
pub type FnCredFindBestCredentialA =
    unsafe extern "system" fn(LPCSTR, DWORD, DWORD, *mut PCREDENTIALA) -> BOOL;
pub type FnCredFindBestCredentialW =
    unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, *mut PCREDENTIALW) -> BOOL;
pub type FnCredFree = unsafe extern "system" fn(PVOID) -> ();
pub type FnCredGetSessionTypes = unsafe extern "system" fn(DWORD, LPDWORD) -> BOOL;
pub type FnCredGetTargetInfoA =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut PCREDENTIAL_TARGET_INFORMATIONA) -> BOOL;
pub type FnCredGetTargetInfoW =
    unsafe extern "system" fn(LPCWSTR, DWORD, *mut PCREDENTIAL_TARGET_INFORMATIONW) -> BOOL;
pub type FnCredIsMarshaledCredentialA = unsafe extern "system" fn(LPCSTR) -> BOOL;
pub type FnCredIsMarshaledCredentialW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
pub type FnCredIsProtectedA = unsafe extern "system" fn(LPSTR, *mut CRED_PROTECTION_TYPE) -> BOOL;
pub type FnCredIsProtectedW = unsafe extern "system" fn(LPWSTR, *mut CRED_PROTECTION_TYPE) -> BOOL;
pub type FnCredMarshalCredentialA =
    unsafe extern "system" fn(CRED_MARSHAL_TYPE, PVOID, *mut LPSTR) -> BOOL;
pub type FnCredMarshalCredentialW =
    unsafe extern "system" fn(CRED_MARSHAL_TYPE, PVOID, *mut LPWSTR) -> BOOL;
pub type FnCredProtectA = unsafe extern "system" fn(
    BOOL,
    LPSTR,
    DWORD,
    LPSTR,
    *mut DWORD,
    *mut CRED_PROTECTION_TYPE,
) -> BOOL;
pub type FnCredProtectW = unsafe extern "system" fn(
    BOOL,
    LPWSTR,
    DWORD,
    LPWSTR,
    *mut DWORD,
    *mut CRED_PROTECTION_TYPE,
) -> BOOL;
pub type FnCredReadA = unsafe extern "system" fn(LPCSTR, DWORD, DWORD, *mut PCREDENTIALA) -> BOOL;
pub type FnCredReadDomainCredentialsA =
    unsafe extern "system" fn(PCREDENTIAL_TARGET_INFORMATIONA, DWORD, *mut DWORD) -> BOOL;
pub type FnCredReadDomainCredentialsW =
    unsafe extern "system" fn(PCREDENTIAL_TARGET_INFORMATIONW, DWORD, *mut DWORD) -> BOOL;
pub type FnCredReadW = unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, *mut PCREDENTIALW) -> BOOL;
pub type FnCredRenameA = unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD, DWORD) -> BOOL;
pub type FnCredRenameW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD, DWORD) -> BOOL;
pub type FnCredUnmarshalCredentialA =
    unsafe extern "system" fn(LPCSTR, PCRED_MARSHAL_TYPE, *mut PVOID) -> BOOL;
pub type FnCredUnmarshalCredentialW =
    unsafe extern "system" fn(LPCWSTR, PCRED_MARSHAL_TYPE, *mut PVOID) -> BOOL;
pub type FnCredUnprotectA =
    unsafe extern "system" fn(BOOL, LPSTR, DWORD, LPSTR, *mut DWORD) -> BOOL;
pub type FnCredUnprotectW =
    unsafe extern "system" fn(BOOL, LPWSTR, DWORD, LPWSTR, *mut DWORD) -> BOOL;
pub type FnCredWriteA = unsafe extern "system" fn(PCREDENTIALA, DWORD) -> BOOL;
pub type FnCredWriteDomainCredentialsA =
    unsafe extern "system" fn(PCREDENTIAL_TARGET_INFORMATIONA, PCREDENTIALA, DWORD) -> BOOL;
pub type FnCredWriteDomainCredentialsW =
    unsafe extern "system" fn(PCREDENTIAL_TARGET_INFORMATIONW, PCREDENTIALW, DWORD) -> BOOL;
pub type FnCredWriteW = unsafe extern "system" fn(PCREDENTIALW, DWORD) -> BOOL;
pub type FnCryptAcquireContextA =
    unsafe extern "system" fn(*mut HCRYPTPROV, LPCSTR, LPCSTR, DWORD, DWORD) -> BOOL;
pub type FnCryptAcquireContextW =
    unsafe extern "system" fn(*mut HCRYPTPROV, LPCWSTR, LPCWSTR, DWORD, DWORD) -> BOOL;
pub type FnCryptContextAddRef = unsafe extern "system" fn(HCRYPTPROV, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptCreateHash =
    unsafe extern "system" fn(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, *mut HCRYPTHASH) -> BOOL;
pub type FnCryptDecrypt =
    unsafe extern "system" fn(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCryptDeriveKey =
    unsafe extern "system" fn(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, *mut HCRYPTKEY) -> BOOL;
pub type FnCryptDestroyHash = unsafe extern "system" fn(HCRYPTHASH) -> BOOL;
pub type FnCryptDestroyKey = unsafe extern "system" fn(HCRYPTKEY) -> BOOL;
pub type FnCryptDuplicateHash =
    unsafe extern "system" fn(HCRYPTHASH, *mut DWORD, DWORD, *mut HCRYPTHASH) -> BOOL;
pub type FnCryptDuplicateKey =
    unsafe extern "system" fn(HCRYPTKEY, *mut DWORD, DWORD, *mut HCRYPTKEY) -> BOOL;
pub type FnCryptEncrypt = unsafe extern "system" fn(
    HCRYPTKEY,
    HCRYPTHASH,
    BOOL,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    DWORD,
) -> BOOL;
pub type FnCryptEnumProviderTypesA =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, *mut DWORD, LPSTR, *mut DWORD) -> BOOL;
pub type FnCryptEnumProviderTypesW =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, *mut DWORD, LPWSTR, *mut DWORD) -> BOOL;
pub type FnCryptEnumProvidersA =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, *mut DWORD, LPSTR, *mut DWORD) -> BOOL;
pub type FnCryptEnumProvidersW =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, *mut DWORD, LPWSTR, *mut DWORD) -> BOOL;
pub type FnCryptExportKey =
    unsafe extern "system" fn(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCryptGenKey =
    unsafe extern "system" fn(HCRYPTPROV, ALG_ID, DWORD, *mut HCRYPTKEY) -> BOOL;
pub type FnCryptGenRandom = unsafe extern "system" fn(HCRYPTPROV, DWORD, *mut BYTE) -> BOOL;
pub type FnCryptGetDefaultProviderA =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, LPSTR, *mut DWORD) -> BOOL;
pub type FnCryptGetDefaultProviderW =
    unsafe extern "system" fn(DWORD, *mut DWORD, DWORD, LPWSTR, *mut DWORD) -> BOOL;
pub type FnCryptGetHashParam =
    unsafe extern "system" fn(HCRYPTHASH, DWORD, *mut BYTE, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptGetKeyParam =
    unsafe extern "system" fn(HCRYPTKEY, DWORD, *mut BYTE, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptGetProvParam =
    unsafe extern "system" fn(HCRYPTPROV, DWORD, *mut BYTE, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptGetUserKey = unsafe extern "system" fn(HCRYPTPROV, DWORD, *mut HCRYPTKEY) -> BOOL;
pub type FnCryptHashData = unsafe extern "system" fn(HCRYPTHASH, *const BYTE, DWORD, DWORD) -> BOOL;
pub type FnCryptHashSessionKey = unsafe extern "system" fn(HCRYPTHASH, HCRYPTKEY, DWORD) -> BOOL;
pub type FnCryptImportKey = unsafe extern "system" fn(
    HCRYPTPROV,
    *const BYTE,
    DWORD,
    HCRYPTKEY,
    DWORD,
    *mut HCRYPTKEY,
) -> BOOL;
pub type FnCryptReleaseContext = unsafe extern "system" fn(HCRYPTPROV, DWORD) -> BOOL;
pub type FnCryptSetHashParam =
    unsafe extern "system" fn(HCRYPTHASH, DWORD, *const BYTE, DWORD) -> BOOL;
pub type FnCryptSetKeyParam =
    unsafe extern "system" fn(HCRYPTKEY, DWORD, *const BYTE, DWORD) -> BOOL;
pub type FnCryptSetProvParam =
    unsafe extern "system" fn(HCRYPTPROV, DWORD, *const BYTE, DWORD) -> BOOL;
pub type FnCryptSetProviderA = unsafe extern "system" fn(LPCSTR, DWORD) -> BOOL;
pub type FnCryptSetProviderExA =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptSetProviderExW =
    unsafe extern "system" fn(LPCWSTR, DWORD, *mut DWORD, DWORD) -> BOOL;
pub type FnCryptSetProviderW = unsafe extern "system" fn(LPCWSTR, DWORD) -> BOOL;
pub type FnCryptSignHashA =
    unsafe extern "system" fn(HCRYPTHASH, DWORD, LPCSTR, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCryptSignHashW =
    unsafe extern "system" fn(HCRYPTHASH, DWORD, LPCWSTR, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCryptVerifySignatureA =
    unsafe extern "system" fn(HCRYPTHASH, *const BYTE, DWORD, HCRYPTKEY, LPCSTR, DWORD) -> BOOL;
pub type FnCryptVerifySignatureW =
    unsafe extern "system" fn(HCRYPTHASH, *const BYTE, DWORD, HCRYPTKEY, LPCWSTR, DWORD) -> BOOL;
pub type FnCveEventWrite = unsafe extern "system" fn(PCWSTR, PCWSTR) -> LONG;
pub type FnDeleteAce = unsafe extern "system" fn(PACL, DWORD) -> BOOL;
pub type FnDeleteService = unsafe extern "system" fn(SC_HANDLE) -> BOOL;
pub type FnDeregisterEventSource = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnDestroyPrivateObjectSecurity =
    unsafe extern "system" fn(*mut PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnDuplicateEncryptionInfoFile =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD, DWORD, *const SECURITY_ATTRIBUTES) -> DWORD;
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
pub type FnEnableTrace =
    unsafe extern "system" fn(ULONG, ULONG, ULONG, LPCGUID, TRACEHANDLE) -> ULONG;
pub type FnEnableTraceEx = unsafe extern "system" fn(
    LPCGUID,
    LPCGUID,
    TRACEHANDLE,
    ULONG,
    UCHAR,
    ULONGLONG,
    ULONGLONG,
    ULONG,
    PEVENT_FILTER_DESCRIPTOR,
) -> ULONG;
pub type FnEnableTraceEx2 = unsafe extern "system" fn(
    TRACEHANDLE,
    LPCGUID,
    ULONG,
    UCHAR,
    ULONGLONG,
    ULONGLONG,
    ULONG,
    PENABLE_TRACE_PARAMETERS,
) -> ULONG;
pub type FnEncryptionDisable = unsafe extern "system" fn(LPCWSTR, BOOL) -> BOOL;
pub type FnEnumDependentServicesA = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    LPENUM_SERVICE_STATUSA,
    DWORD,
    LPDWORD,
    LPDWORD,
) -> BOOL;
pub type FnEnumDependentServicesW = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    LPENUM_SERVICE_STATUSW,
    DWORD,
    LPDWORD,
    LPDWORD,
) -> BOOL;
pub type FnEnumDynamicTimeZoneInformation =
    unsafe extern "system" fn(DWORD, PDYNAMIC_TIME_ZONE_INFORMATION) -> DWORD;
pub type FnEnumServicesStatusA = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    DWORD,
    LPENUM_SERVICE_STATUSA,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
) -> BOOL;
pub type FnEnumServicesStatusExA = unsafe extern "system" fn(
    SC_HANDLE,
    SC_ENUM_TYPE,
    DWORD,
    DWORD,
    LPBYTE,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPCSTR,
) -> BOOL;
pub type FnEnumServicesStatusExW = unsafe extern "system" fn(
    SC_HANDLE,
    SC_ENUM_TYPE,
    DWORD,
    DWORD,
    LPBYTE,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
    LPCWSTR,
) -> BOOL;
pub type FnEnumServicesStatusW = unsafe extern "system" fn(
    SC_HANDLE,
    DWORD,
    DWORD,
    LPENUM_SERVICE_STATUSW,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD,
) -> BOOL;
pub type FnEnumerateTraceGuids =
    unsafe extern "system" fn(*mut PTRACE_GUID_PROPERTIES, ULONG, PULONG) -> ULONG;
pub type FnEnumerateTraceGuidsEx =
    unsafe extern "system" fn(TRACE_QUERY_INFO_CLASS, PVOID, ULONG, PVOID, ULONG, PULONG) -> ULONG;
pub type FnEqualDomainSid = unsafe extern "system" fn(PSID, PSID, *mut BOOL) -> BOOL;
pub type FnEqualPrefixSid = unsafe extern "system" fn(PSID, PSID) -> BOOL;
pub type FnEqualSid = unsafe extern "system" fn(PSID, PSID) -> BOOL;
pub type FnEventAccessControl =
    unsafe extern "system" fn(LPGUID, ULONG, PSID, ULONG, BOOLEAN) -> ULONG;
pub type FnEventAccessQuery =
    unsafe extern "system" fn(LPGUID, PSECURITY_DESCRIPTOR, PULONG) -> ULONG;
pub type FnEventAccessRemove = unsafe extern "system" fn(LPGUID) -> ULONG;
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
pub type FnFindFirstFreeAce = unsafe extern "system" fn(PACL, *mut LPVOID) -> BOOL;
pub type FnFlushTraceA =
    unsafe extern "system" fn(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnFlushTraceW =
    unsafe extern "system" fn(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnFreeEncryptedFileMetadata = unsafe extern "system" fn(PBYTE) -> ();
pub type FnFreeEncryptionCertificateHashList =
    unsafe extern "system" fn(PENCRYPTION_CERTIFICATE_HASH_LIST) -> ();
pub type FnFreeInheritedFromArray =
    unsafe extern "system" fn(PINHERITED_FROMW, USHORT, PFN_OBJECT_MGR_FUNCTS) -> DWORD;
pub type FnFreeSid = unsafe extern "system" fn(PSID) -> PVOID;
pub type FnGetAce = unsafe extern "system" fn(PACL, DWORD, *mut LPVOID) -> BOOL;
pub type FnGetAclInformation =
    unsafe extern "system" fn(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS) -> BOOL;
pub type FnGetAuditedPermissionsFromAclA =
    unsafe extern "system" fn(PACL, PTRUSTEE_A, PACCESS_MASK, PACCESS_MASK) -> DWORD;
pub type FnGetAuditedPermissionsFromAclW =
    unsafe extern "system" fn(PACL, PTRUSTEE_W, PACCESS_MASK, PACCESS_MASK) -> DWORD;
pub type FnGetCurrentHwProfileA = unsafe extern "system" fn(LPHW_PROFILE_INFOA) -> BOOL;
pub type FnGetCurrentHwProfileW = unsafe extern "system" fn(LPHW_PROFILE_INFOW) -> BOOL;
pub type FnGetDynamicTimeZoneInformationEffectiveYears =
    unsafe extern "system" fn(PDYNAMIC_TIME_ZONE_INFORMATION, LPDWORD, LPDWORD) -> DWORD;
pub type FnGetEffectiveRightsFromAclA =
    unsafe extern "system" fn(PACL, PTRUSTEE_A, PACCESS_MASK) -> DWORD;
pub type FnGetEffectiveRightsFromAclW =
    unsafe extern "system" fn(PACL, PTRUSTEE_W, PACCESS_MASK) -> DWORD;
pub type FnGetEncryptedFileMetadata =
    unsafe extern "system" fn(LPCWSTR, PDWORD, *mut PBYTE) -> DWORD;
pub type FnGetExplicitEntriesFromAclA =
    unsafe extern "system" fn(PACL, PULONG, *mut PEXPLICIT_ACCESS_A) -> DWORD;
pub type FnGetExplicitEntriesFromAclW =
    unsafe extern "system" fn(PACL, PULONG, *mut PEXPLICIT_ACCESS_W) -> DWORD;
pub type FnGetFileSecurityW = unsafe extern "system" fn(
    LPCWSTR,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnGetInheritanceSourceA = unsafe extern "system" fn(
    LPSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    BOOL,
    DWORD,
    PACL,
    PFN_OBJECT_MGR_FUNCTS,
    PGENERIC_MAPPING,
    PINHERITED_FROMA,
) -> DWORD;
pub type FnGetInheritanceSourceW = unsafe extern "system" fn(
    LPWSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    BOOL,
    DWORD,
    PACL,
    PFN_OBJECT_MGR_FUNCTS,
    PGENERIC_MAPPING,
    PINHERITED_FROMW,
) -> DWORD;
pub type FnGetKernelObjectSecurity = unsafe extern "system" fn(
    HANDLE,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnGetLengthSid = unsafe extern "system" fn(PSID) -> DWORD;
pub type FnGetLocalManagedApplicationData =
    unsafe extern "system" fn(LPWSTR, *mut LPWSTR, *mut LPWSTR) -> ();
pub type FnGetLocalManagedApplications =
    unsafe extern "system" fn(BOOL, LPDWORD, *mut PMANAGEDAPPLICATION) -> DWORD;
pub type FnGetManagedApplicationCategories =
    unsafe extern "system" fn(DWORD, *mut APPCATEGORYINFOLIST) -> DWORD;
pub type FnGetManagedApplications =
    unsafe extern "system" fn(*mut GUID, DWORD, DWORD, LPDWORD, *mut PMANAGEDAPPLICATION) -> DWORD;
pub type FnGetMultipleTrusteeA = unsafe extern "system" fn(PTRUSTEE_A) -> PTRUSTEE_A;
pub type FnGetMultipleTrusteeOperationA =
    unsafe extern "system" fn(PTRUSTEE_A) -> MULTIPLE_TRUSTEE_OPERATION;
pub type FnGetMultipleTrusteeOperationW =
    unsafe extern "system" fn(PTRUSTEE_W) -> MULTIPLE_TRUSTEE_OPERATION;
pub type FnGetMultipleTrusteeW = unsafe extern "system" fn(PTRUSTEE_W) -> PTRUSTEE_W;
pub type FnGetNamedSecurityInfoA = unsafe extern "system" fn(
    LPCSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    *mut PSID,
    *mut PSID,
    *mut PACL,
    *mut PACL,
    *mut PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnGetNamedSecurityInfoW = unsafe extern "system" fn(
    LPCWSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    *mut PSID,
    *mut PSID,
    *mut PACL,
    *mut PACL,
    *mut PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnGetPrivateObjectSecurity = unsafe extern "system" fn(
    PSECURITY_DESCRIPTOR,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    PDWORD,
) -> BOOL;
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
pub type FnGetSecurityInfo = unsafe extern "system" fn(
    HANDLE,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    *mut PSID,
    *mut PSID,
    *mut PACL,
    *mut PACL,
    *mut PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnGetServiceDisplayNameA =
    unsafe extern "system" fn(SC_HANDLE, LPCSTR, LPSTR, LPDWORD) -> BOOL;
pub type FnGetServiceDisplayNameW =
    unsafe extern "system" fn(SC_HANDLE, LPCWSTR, LPWSTR, LPDWORD) -> BOOL;
pub type FnGetServiceKeyNameA =
    unsafe extern "system" fn(SC_HANDLE, LPCSTR, LPSTR, LPDWORD) -> BOOL;
pub type FnGetServiceKeyNameW =
    unsafe extern "system" fn(SC_HANDLE, LPCWSTR, LPWSTR, LPDWORD) -> BOOL;
pub type FnGetSidIdentifierAuthority = unsafe extern "system" fn(PSID) -> PSID_IDENTIFIER_AUTHORITY;
pub type FnGetSidLengthRequired = unsafe extern "system" fn(UCHAR) -> DWORD;
pub type FnGetSidSubAuthority = unsafe extern "system" fn(PSID, DWORD) -> PDWORD;
pub type FnGetSidSubAuthorityCount = unsafe extern "system" fn(PSID) -> PUCHAR;
pub type FnGetThreadWaitChain = unsafe extern "system" fn(
    HWCT,
    DWORD_PTR,
    DWORD,
    DWORD,
    LPDWORD,
    PWAITCHAIN_NODE_INFO,
    LPBOOL,
) -> BOOL;
pub type FnGetTokenInformation =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD) -> BOOL;
pub type FnGetTraceEnableFlags = unsafe extern "system" fn(TRACEHANDLE) -> ULONG;
pub type FnGetTraceEnableLevel = unsafe extern "system" fn(TRACEHANDLE) -> UCHAR;
pub type FnGetTraceLoggerHandle = unsafe extern "system" fn(PVOID) -> TRACEHANDLE;
pub type FnGetTrusteeFormA = unsafe extern "system" fn(PTRUSTEE_A) -> TRUSTEE_FORM;
pub type FnGetTrusteeFormW = unsafe extern "system" fn(PTRUSTEE_W) -> TRUSTEE_FORM;
pub type FnGetTrusteeNameA = unsafe extern "system" fn(PTRUSTEE_A) -> LPSTR;
pub type FnGetTrusteeNameW = unsafe extern "system" fn(PTRUSTEE_W) -> LPWSTR;
pub type FnGetTrusteeTypeA = unsafe extern "system" fn(PTRUSTEE_A) -> TRUSTEE_TYPE;
pub type FnGetTrusteeTypeW = unsafe extern "system" fn(PTRUSTEE_W) -> TRUSTEE_TYPE;
pub type FnGetUserNameA = unsafe extern "system" fn(LPSTR, LPDWORD) -> BOOL;
pub type FnGetUserNameW = unsafe extern "system" fn(LPWSTR, LPDWORD) -> BOOL;
pub type FnGetWindowsAccountDomainSid = unsafe extern "system" fn(PSID, PSID, *mut DWORD) -> BOOL;
pub type FnI_QueryTagInformation =
    unsafe extern "system" fn(LPCWSTR, TAG_INFO_LEVEL, PVOID) -> DWORD;
pub type FnImpersonateAnonymousToken = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateLoggedOnUser = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateNamedPipeClient = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnImpersonateSelf = unsafe extern "system" fn(SECURITY_IMPERSONATION_LEVEL) -> BOOL;
pub type FnInitializeAcl = unsafe extern "system" fn(PACL, DWORD, DWORD) -> BOOL;
pub type FnInitializeSecurityDescriptor =
    unsafe extern "system" fn(PSECURITY_DESCRIPTOR, DWORD) -> BOOL;
pub type FnInitializeSid = unsafe extern "system" fn(PSID, PSID_IDENTIFIER_AUTHORITY, BYTE) -> BOOL;
pub type FnInitiateShutdownA =
    unsafe extern "system" fn(LPSTR, LPSTR, DWORD, DWORD, DWORD) -> DWORD;
pub type FnInitiateShutdownW =
    unsafe extern "system" fn(LPWSTR, LPWSTR, DWORD, DWORD, DWORD) -> DWORD;
pub type FnInitiateSystemShutdownA =
    unsafe extern "system" fn(LPSTR, LPSTR, DWORD, BOOL, BOOL) -> BOOL;
pub type FnInitiateSystemShutdownExA =
    unsafe extern "system" fn(LPSTR, LPSTR, DWORD, BOOL, BOOL, DWORD) -> BOOL;
pub type FnInitiateSystemShutdownExW =
    unsafe extern "system" fn(LPWSTR, LPWSTR, DWORD, BOOL, BOOL, DWORD) -> BOOL;
pub type FnInitiateSystemShutdownW =
    unsafe extern "system" fn(LPWSTR, LPWSTR, DWORD, BOOL, BOOL) -> BOOL;
pub type FnInstallApplication = unsafe extern "system" fn(PINSTALLDATA) -> DWORD;
pub type FnIsTokenRestricted = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnIsTokenUntrusted = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnIsValidAcl = unsafe extern "system" fn(PACL) -> BOOL;
pub type FnIsValidSecurityDescriptor = unsafe extern "system" fn(PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnIsValidSid = unsafe extern "system" fn(PSID) -> BOOL;
pub type FnIsWellKnownSid = unsafe extern "system" fn(PSID, WELL_KNOWN_SID_TYPE) -> BOOL;
pub type FnLockServiceDatabase = unsafe extern "system" fn(SC_HANDLE) -> SC_LOCK;
pub type FnLogonUserA =
    unsafe extern "system" fn(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE) -> BOOL;
pub type FnLogonUserExA = unsafe extern "system" fn(
    LPCSTR,
    LPCSTR,
    LPCSTR,
    DWORD,
    DWORD,
    PHANDLE,
    *mut PSID,
    *mut PVOID,
    LPDWORD,
    PQUOTA_LIMITS,
) -> BOOL;
pub type FnLogonUserExW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
    DWORD,
    DWORD,
    PHANDLE,
    *mut PSID,
    *mut PVOID,
    LPDWORD,
    PQUOTA_LIMITS,
) -> BOOL;
pub type FnLogonUserW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE) -> BOOL;
pub type FnLookupAccountNameA = unsafe extern "system" fn(
    LPCSTR,
    LPCSTR,
    PSID,
    LPDWORD,
    LPCSTR,
    LPDWORD,
    PSID_NAME_USE,
) -> BOOL;
pub type FnLookupAccountNameW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    PSID,
    LPDWORD,
    LPCWSTR,
    LPDWORD,
    PSID_NAME_USE,
) -> BOOL;
pub type FnLookupAccountSidA =
    unsafe extern "system" fn(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE) -> BOOL;
pub type FnLookupAccountSidW = unsafe extern "system" fn(
    LPCWSTR,
    PSID,
    LPWSTR,
    LPDWORD,
    LPWSTR,
    LPDWORD,
    PSID_NAME_USE,
) -> BOOL;
pub type FnLookupPrivilegeNameA = unsafe extern "system" fn(LPCSTR, PLUID, LPSTR, LPDWORD) -> BOOL;
pub type FnLookupPrivilegeNameW =
    unsafe extern "system" fn(LPCWSTR, PLUID, LPWSTR, LPDWORD) -> BOOL;
pub type FnLookupPrivilegeValueA = unsafe extern "system" fn(LPCSTR, LPCSTR, PLUID) -> BOOL;
pub type FnLookupPrivilegeValueW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, PLUID) -> BOOL;
pub type FnLookupSecurityDescriptorPartsA = unsafe extern "system" fn(
    *mut PTRUSTEE_A,
    *mut PTRUSTEE_A,
    PULONG,
    *mut PEXPLICIT_ACCESS_A,
    PULONG,
    *mut PEXPLICIT_ACCESS_A,
    PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnLookupSecurityDescriptorPartsW = unsafe extern "system" fn(
    *mut PTRUSTEE_W,
    *mut PTRUSTEE_W,
    PULONG,
    *mut PEXPLICIT_ACCESS_W,
    PULONG,
    *mut PEXPLICIT_ACCESS_W,
    PSECURITY_DESCRIPTOR,
) -> DWORD;
pub type FnLsaAddAccountRights =
    unsafe extern "system" fn(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG) -> NTSTATUS;
pub type FnLsaAddPrivilegesToAccount =
    unsafe extern "system" fn(LSA_HANDLE, PPRIVILEGE_SET) -> NTSTATUS;
pub type FnLsaClearAuditLog = unsafe extern "system" fn(LSA_HANDLE) -> NTSTATUS;
pub type FnLsaClose = unsafe extern "system" fn(LSA_HANDLE) -> NTSTATUS;
pub type FnLsaCreateAccount =
    unsafe extern "system" fn(LSA_HANDLE, PSID, ACCESS_MASK, PLSA_HANDLE) -> NTSTATUS;
pub type FnLsaCreateSecret = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaCreateTrustedDomain = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_TRUST_INFORMATION,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaCreateTrustedDomainEx = unsafe extern "system" fn(
    LSA_HANDLE,
    PTRUSTED_DOMAIN_INFORMATION_EX,
    PTRUSTED_DOMAIN_AUTH_INFORMATION,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaDelete = unsafe extern "system" fn(LSA_HANDLE) -> NTSTATUS;
pub type FnLsaDeleteTrustedDomain = unsafe extern "system" fn(LSA_HANDLE, PSID) -> NTSTATUS;
pub type FnLsaEnumerateAccountRights =
    unsafe extern "system" fn(LSA_HANDLE, PSID, *mut PLSA_UNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnLsaEnumerateAccounts = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_ENUMERATION_HANDLE,
    *mut PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnLsaEnumerateAccountsWithUserRight =
    unsafe extern "system" fn(LSA_HANDLE, PLSA_UNICODE_STRING, *mut PVOID, PULONG) -> NTSTATUS;
pub type FnLsaEnumeratePrivileges = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_ENUMERATION_HANDLE,
    *mut PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnLsaEnumeratePrivilegesOfAccount =
    unsafe extern "system" fn(LSA_HANDLE, *mut PPRIVILEGE_SET) -> NTSTATUS;
pub type FnLsaEnumerateTrustedDomains = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_ENUMERATION_HANDLE,
    *mut PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnLsaEnumerateTrustedDomainsEx = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_ENUMERATION_HANDLE,
    *mut PVOID,
    ULONG,
    PULONG,
) -> NTSTATUS;
pub type FnLsaFreeMemory = unsafe extern "system" fn(PVOID) -> NTSTATUS;
pub type FnLsaGetAppliedCAPIDs = unsafe extern "system" fn(PLSA_UNICODE_STRING, PULONG) -> NTSTATUS;
pub type FnLsaGetDeviceRegistrationInfo =
    unsafe extern "system" fn(*mut PLSA_REGISTRATION_INFO) -> NTSTATUS;
pub type FnLsaGetQuotasForAccount =
    unsafe extern "system" fn(LSA_HANDLE, PQUOTA_LIMITS) -> NTSTATUS;
pub type FnLsaGetRemoteUserName = unsafe extern "system" fn(
    PLSA_UNICODE_STRING,
    *mut PLSA_UNICODE_STRING,
    *mut PLSA_UNICODE_STRING,
) -> NTSTATUS;
pub type FnLsaGetSystemAccessAccount = unsafe extern "system" fn(LSA_HANDLE, PULONG) -> NTSTATUS;
pub type FnLsaGetUserName =
    unsafe extern "system" fn(*mut PLSA_UNICODE_STRING, *mut PLSA_UNICODE_STRING) -> NTSTATUS;
pub type FnLsaLookupNames = unsafe extern "system" fn(
    LSA_HANDLE,
    ULONG,
    PLSA_UNICODE_STRING,
    *mut PLSA_REFERENCED_DOMAIN_LIST,
    *mut PLSA_TRANSLATED_SID,
) -> NTSTATUS;
pub type FnLsaLookupNames2 = unsafe extern "system" fn(
    LSA_HANDLE,
    ULONG,
    ULONG,
    PLSA_UNICODE_STRING,
    *mut PLSA_REFERENCED_DOMAIN_LIST,
    *mut PLSA_TRANSLATED_SID2,
) -> NTSTATUS;
pub type FnLsaLookupPrivilegeDisplayName = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    *mut PLSA_UNICODE_STRING,
    PSHORT,
) -> NTSTATUS;
pub type FnLsaLookupPrivilegeName =
    unsafe extern "system" fn(LSA_HANDLE, PLUID, *mut PLSA_UNICODE_STRING) -> NTSTATUS;
pub type FnLsaLookupPrivilegeValue =
    unsafe extern "system" fn(LSA_HANDLE, PLSA_UNICODE_STRING, PLUID) -> NTSTATUS;
pub type FnLsaLookupSids = unsafe extern "system" fn(
    LSA_HANDLE,
    ULONG,
    *mut PSID,
    *mut PLSA_REFERENCED_DOMAIN_LIST,
    *mut PLSA_TRANSLATED_NAME,
) -> NTSTATUS;
pub type FnLsaLookupSids2 = unsafe extern "system" fn(
    LSA_HANDLE,
    ULONG,
    ULONG,
    *mut PSID,
    *mut PLSA_REFERENCED_DOMAIN_LIST,
    *mut PLSA_TRANSLATED_NAME,
) -> NTSTATUS;
pub type FnLsaNtStatusToWinError = unsafe extern "system" fn(NTSTATUS) -> ULONG;
pub type FnLsaOpenAccount =
    unsafe extern "system" fn(LSA_HANDLE, PSID, ACCESS_MASK, PLSA_HANDLE) -> NTSTATUS;
pub type FnLsaOpenPolicy = unsafe extern "system" fn(
    PLSA_UNICODE_STRING,
    PLSA_OBJECT_ATTRIBUTES,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaOpenPolicySce = unsafe extern "system" fn(
    PLSA_UNICODE_STRING,
    PLSA_OBJECT_ATTRIBUTES,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaOpenSecret = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaOpenTrustedDomain =
    unsafe extern "system" fn(LSA_HANDLE, PSID, ACCESS_MASK, PLSA_HANDLE) -> NTSTATUS;
pub type FnLsaOpenTrustedDomainByName = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    ACCESS_MASK,
    PLSA_HANDLE,
) -> NTSTATUS;
pub type FnLsaQueryCAPs =
    unsafe extern "system" fn(*mut PSID, ULONG, *mut PCENTRAL_ACCESS_POLICY, PULONG) -> NTSTATUS;
pub type FnLsaQueryDomainInformationPolicy =
    unsafe extern "system" fn(LSA_HANDLE, POLICY_DOMAIN_INFORMATION_CLASS, *mut PVOID) -> NTSTATUS;
pub type FnLsaQueryForestTrustInformation = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    *mut PLSA_FOREST_TRUST_INFORMATION,
) -> NTSTATUS;
pub type FnLsaQueryInfoTrustedDomain =
    unsafe extern "system" fn(LSA_HANDLE, TRUSTED_INFORMATION_CLASS, *mut PVOID) -> NTSTATUS;
pub type FnLsaQueryInformationPolicy =
    unsafe extern "system" fn(LSA_HANDLE, POLICY_INFORMATION_CLASS, *mut PVOID) -> NTSTATUS;
pub type FnLsaQuerySecret = unsafe extern "system" fn(
    LSA_HANDLE,
    *mut PLSA_UNICODE_STRING,
    PLARGE_INTEGER,
    *mut PLSA_UNICODE_STRING,
    PLARGE_INTEGER,
) -> NTSTATUS;
pub type FnLsaQuerySecurityObject = unsafe extern "system" fn(
    LSA_HANDLE,
    SECURITY_INFORMATION,
    *mut PSECURITY_DESCRIPTOR,
) -> NTSTATUS;
pub type FnLsaQueryTrustedDomainInfo =
    unsafe extern "system" fn(LSA_HANDLE, PSID, TRUSTED_INFORMATION_CLASS, *mut PVOID) -> NTSTATUS;
pub type FnLsaQueryTrustedDomainInfoByName = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    TRUSTED_INFORMATION_CLASS,
    *mut PVOID,
) -> NTSTATUS;
pub type FnLsaRemoveAccountRights =
    unsafe extern "system" fn(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG) -> NTSTATUS;
pub type FnLsaRemovePrivilegesFromAccount =
    unsafe extern "system" fn(LSA_HANDLE, BOOLEAN, PPRIVILEGE_SET) -> NTSTATUS;
pub type FnLsaRetrievePrivateData = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    *mut PLSA_UNICODE_STRING,
) -> NTSTATUS;
pub type FnLsaSetCAPs = unsafe extern "system" fn(PLSA_UNICODE_STRING, ULONG, ULONG) -> NTSTATUS;
pub type FnLsaSetDomainInformationPolicy =
    unsafe extern "system" fn(LSA_HANDLE, POLICY_DOMAIN_INFORMATION_CLASS, PVOID) -> NTSTATUS;
pub type FnLsaSetForestTrustInformation = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    PLSA_FOREST_TRUST_INFORMATION,
    BOOLEAN,
    *mut PLSA_FOREST_TRUST_COLLISION_INFORMATION,
) -> NTSTATUS;
pub type FnLsaSetInformationPolicy =
    unsafe extern "system" fn(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID) -> NTSTATUS;
pub type FnLsaSetInformationTrustedDomain =
    unsafe extern "system" fn(LSA_HANDLE, TRUSTED_INFORMATION_CLASS, PVOID) -> NTSTATUS;
pub type FnLsaSetQuotasForAccount =
    unsafe extern "system" fn(LSA_HANDLE, PQUOTA_LIMITS) -> NTSTATUS;
pub type FnLsaSetSecret =
    unsafe extern "system" fn(LSA_HANDLE, PLSA_UNICODE_STRING, PLSA_UNICODE_STRING) -> NTSTATUS;
pub type FnLsaSetSecurityObject =
    unsafe extern "system" fn(LSA_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> NTSTATUS;
pub type FnLsaSetSystemAccessAccount = unsafe extern "system" fn(LSA_HANDLE, ULONG) -> NTSTATUS;
pub type FnLsaSetTrustedDomainInfoByName = unsafe extern "system" fn(
    LSA_HANDLE,
    PLSA_UNICODE_STRING,
    TRUSTED_INFORMATION_CLASS,
    PVOID,
) -> NTSTATUS;
pub type FnLsaSetTrustedDomainInformation =
    unsafe extern "system" fn(LSA_HANDLE, PSID, TRUSTED_INFORMATION_CLASS, PVOID) -> NTSTATUS;
pub type FnLsaStorePrivateData =
    unsafe extern "system" fn(LSA_HANDLE, PLSA_UNICODE_STRING, PLSA_UNICODE_STRING) -> NTSTATUS;
pub type FnMSChapSrvChangePassword = unsafe extern "system" fn(
    PWSTR,
    PWSTR,
    BOOLEAN,
    PLM_OWF_PASSWORD,
    PLM_OWF_PASSWORD,
    PNT_OWF_PASSWORD,
    PNT_OWF_PASSWORD,
) -> DWORD;
pub type FnMSChapSrvChangePassword2 = unsafe extern "system" fn(
    PWSTR,
    PWSTR,
    PSAMPR_ENCRYPTED_USER_PASSWORD,
    PENCRYPTED_NT_OWF_PASSWORD,
    BOOLEAN,
    PSAMPR_ENCRYPTED_USER_PASSWORD,
    PENCRYPTED_LM_OWF_PASSWORD,
) -> DWORD;
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
pub type FnNotifyBootConfigStatus = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnNotifyServiceStatusChangeA =
    unsafe extern "system" fn(SC_HANDLE, DWORD, PSERVICE_NOTIFYA) -> DWORD;
pub type FnNotifyServiceStatusChangeW =
    unsafe extern "system" fn(SC_HANDLE, DWORD, PSERVICE_NOTIFYW) -> DWORD;
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
pub type FnOpenProcessToken = unsafe extern "system" fn(HANDLE, DWORD, PHANDLE) -> BOOL;
pub type FnOpenSCManagerA = unsafe extern "system" fn(LPCSTR, LPCSTR, DWORD) -> SC_HANDLE;
pub type FnOpenSCManagerW = unsafe extern "system" fn(LPCWSTR, LPCWSTR, DWORD) -> SC_HANDLE;
pub type FnOpenServiceA = unsafe extern "system" fn(SC_HANDLE, LPCSTR, DWORD) -> SC_HANDLE;
pub type FnOpenServiceW = unsafe extern "system" fn(SC_HANDLE, LPCWSTR, DWORD) -> SC_HANDLE;
pub type FnOpenThreadToken = unsafe extern "system" fn(HANDLE, DWORD, BOOL, PHANDLE) -> BOOL;
pub type FnOpenThreadWaitChainSession =
    unsafe extern "system" fn(DWORD, PWAITCHAINCALLBACK) -> HWCT;
pub type FnOpenTraceA = unsafe extern "system" fn(PEVENT_TRACE_LOGFILEA) -> TRACEHANDLE;
pub type FnOpenTraceW = unsafe extern "system" fn(PEVENT_TRACE_LOGFILEW) -> TRACEHANDLE;
pub type FnPerfAddCounters =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTER_IDENTIFIER, DWORD) -> ULONG;
pub type FnPerfCloseQueryHandle = unsafe extern "system" fn(HANDLE) -> ULONG;
pub type FnPerfCreateInstance =
    unsafe extern "system" fn(HANDLE, LPCGUID, PCWSTR, ULONG) -> PPERF_COUNTERSET_INSTANCE;
pub type FnPerfDecrementULongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG) -> ULONG;
pub type FnPerfDecrementULongLongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG) -> ULONG;
pub type FnPerfDeleteCounters =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTER_IDENTIFIER, DWORD) -> ULONG;
pub type FnPerfDeleteInstance =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE) -> ULONG;
pub type FnPerfEnumerateCounterSet =
    unsafe extern "system" fn(LPCWSTR, LPGUID, DWORD, LPDWORD) -> ULONG;
pub type FnPerfEnumerateCounterSetInstances =
    unsafe extern "system" fn(LPCWSTR, LPCGUID, PPERF_INSTANCE_HEADER, DWORD, LPDWORD) -> ULONG;
pub type FnPerfIncrementULongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG) -> ULONG;
pub type FnPerfIncrementULongLongCounterValue =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG) -> ULONG;
pub type FnPerfOpenQueryHandle = unsafe extern "system" fn(LPCWSTR, *mut HANDLE) -> ULONG;
pub type FnPerfQueryCounterData =
    unsafe extern "system" fn(HANDLE, PPERF_DATA_HEADER, DWORD, LPDWORD) -> ULONG;
pub type FnPerfQueryCounterInfo =
    unsafe extern "system" fn(HANDLE, PPERF_COUNTER_IDENTIFIER, DWORD, LPDWORD) -> ULONG;
pub type FnPerfQueryCounterSetRegistrationInfo = unsafe extern "system" fn(
    LPCWSTR,
    LPCGUID,
    PerfRegInfoType,
    DWORD,
    LPBYTE,
    DWORD,
    LPDWORD,
) -> ULONG;
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
pub type FnPrivilegeCheck = unsafe extern "system" fn(HANDLE, PPRIVILEGE_SET, LPBOOL) -> BOOL;
pub type FnPrivilegedServiceAuditAlarmW =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, HANDLE, PPRIVILEGE_SET, BOOL) -> BOOL;
pub type FnProcessTrace =
    unsafe extern "system" fn(PTRACEHANDLE, ULONG, LPFILETIME, LPFILETIME) -> ULONG;
pub type FnQueryAllTracesA =
    unsafe extern "system" fn(*mut PEVENT_TRACE_PROPERTIES, ULONG, PULONG) -> ULONG;
pub type FnQueryAllTracesW =
    unsafe extern "system" fn(*mut PEVENT_TRACE_PROPERTIES, ULONG, PULONG) -> ULONG;
pub type FnQueryRecoveryAgentsOnEncryptedFile =
    unsafe extern "system" fn(LPCWSTR, *mut PENCRYPTION_CERTIFICATE_HASH_LIST) -> DWORD;
pub type FnQuerySecurityAccessMask = unsafe extern "system" fn(SECURITY_INFORMATION, LPDWORD) -> ();
pub type FnQueryServiceConfig2A =
    unsafe extern "system" fn(SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceConfig2W =
    unsafe extern "system" fn(SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceConfigA =
    unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceConfigW =
    unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceDynamicInformation =
    unsafe extern "system" fn(SERVICE_STATUS_HANDLE, DWORD, *mut PVOID) -> BOOL;
pub type FnQueryServiceLockStatusA =
    unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_LOCK_STATUSA, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceLockStatusW =
    unsafe extern "system" fn(SC_HANDLE, LPQUERY_SERVICE_LOCK_STATUSW, DWORD, LPDWORD) -> BOOL;
pub type FnQueryServiceObjectSecurity = unsafe extern "system" fn(
    SC_HANDLE,
    SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnQueryServiceStatus = unsafe extern "system" fn(SC_HANDLE, LPSERVICE_STATUS) -> BOOL;
pub type FnQueryServiceStatusEx =
    unsafe extern "system" fn(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD) -> BOOL;
pub type FnQueryTraceA =
    unsafe extern "system" fn(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnQueryTraceProcessingHandle = unsafe extern "system" fn(
    TRACEHANDLE,
    ETW_PROCESS_HANDLE_INFO_TYPE,
    PVOID,
    ULONG,
    PVOID,
    ULONG,
    PULONG,
) -> ULONG;
pub type FnQueryTraceW =
    unsafe extern "system" fn(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnQueryUsersOnEncryptedFile =
    unsafe extern "system" fn(LPCWSTR, *mut PENCRYPTION_CERTIFICATE_HASH_LIST) -> DWORD;
pub type FnRegCloseKey = unsafe extern "system" fn(HKEY) -> LSTATUS;
pub type FnRegConnectRegistryA = unsafe extern "system" fn(LPCSTR, HKEY, PHKEY) -> LSTATUS;
pub type FnRegConnectRegistryExA = unsafe extern "system" fn(LPCSTR, HKEY, ULONG, PHKEY) -> LSTATUS;
pub type FnRegConnectRegistryExW =
    unsafe extern "system" fn(LPCWSTR, HKEY, ULONG, PHKEY) -> LSTATUS;
pub type FnRegConnectRegistryW = unsafe extern "system" fn(LPCWSTR, HKEY, PHKEY) -> LSTATUS;
pub type FnRegCopyTreeA = unsafe extern "system" fn(HKEY, LPCSTR, HKEY) -> LSTATUS;
pub type FnRegCopyTreeW = unsafe extern "system" fn(HKEY, LPCWSTR, HKEY) -> LSTATUS;
pub type FnRegCreateKeyA = unsafe extern "system" fn(HKEY, LPCSTR, PHKEY) -> LSTATUS;
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
pub type FnRegCreateKeyTransactedA = unsafe extern "system" fn(
    HKEY,
    LPCSTR,
    DWORD,
    LPSTR,
    DWORD,
    REGSAM,
    LPSECURITY_ATTRIBUTES,
    PHKEY,
    LPDWORD,
    HANDLE,
    PVOID,
) -> LSTATUS;
pub type FnRegCreateKeyTransactedW = unsafe extern "system" fn(
    HKEY,
    LPCWSTR,
    DWORD,
    LPWSTR,
    DWORD,
    REGSAM,
    LPSECURITY_ATTRIBUTES,
    PHKEY,
    LPDWORD,
    HANDLE,
    PVOID,
) -> LSTATUS;
pub type FnRegCreateKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, PHKEY) -> LSTATUS;
pub type FnRegDeleteKeyA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegDeleteKeyExA = unsafe extern "system" fn(HKEY, LPCSTR, REGSAM, DWORD) -> LSTATUS;
pub type FnRegDeleteKeyExW = unsafe extern "system" fn(HKEY, LPCWSTR, REGSAM, DWORD) -> LSTATUS;
pub type FnRegDeleteKeyTransactedA =
    unsafe extern "system" fn(HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID) -> LSTATUS;
pub type FnRegDeleteKeyTransactedW =
    unsafe extern "system" fn(HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID) -> LSTATUS;
pub type FnRegDeleteKeyValueA = unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR) -> LSTATUS;
pub type FnRegDeleteKeyValueW = unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR) -> LSTATUS;
pub type FnRegDeleteKeyW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegDeleteTreeA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegDeleteTreeW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegDeleteValueA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegDeleteValueW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegDisablePredefinedCache = unsafe extern "system" fn() -> LSTATUS;
pub type FnRegDisablePredefinedCacheEx = unsafe extern "system" fn() -> LSTATUS;
pub type FnRegDisableReflectionKey = unsafe extern "system" fn(HKEY) -> LONG;
pub type FnRegEnableReflectionKey = unsafe extern "system" fn(HKEY) -> LONG;
pub type FnRegEnumKeyA = unsafe extern "system" fn(HKEY, DWORD, LPSTR, DWORD) -> LSTATUS;
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
pub type FnRegEnumKeyW = unsafe extern "system" fn(HKEY, DWORD, LPWSTR, DWORD) -> LSTATUS;
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
pub type FnRegOpenKeyA = unsafe extern "system" fn(HKEY, LPCSTR, PHKEY) -> LSTATUS;
pub type FnRegOpenKeyExA = unsafe extern "system" fn(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOpenKeyExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOpenKeyTransactedA =
    unsafe extern "system" fn(HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID) -> LSTATUS;
pub type FnRegOpenKeyTransactedW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID) -> LSTATUS;
pub type FnRegOpenKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, PHKEY) -> LSTATUS;
pub type FnRegOpenUserClassesRoot =
    unsafe extern "system" fn(HANDLE, DWORD, REGSAM, PHKEY) -> LSTATUS;
pub type FnRegOverridePredefKey = unsafe extern "system" fn(HKEY, HKEY) -> LSTATUS;
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
pub type FnRegQueryReflectionKey = unsafe extern "system" fn(HKEY, *mut BOOL) -> LONG;
pub type FnRegQueryValueA = unsafe extern "system" fn(HKEY, LPCSTR, LPSTR, PLONG) -> LSTATUS;
pub type FnRegQueryValueExA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) -> LSTATUS;
pub type FnRegQueryValueExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) -> LSTATUS;
pub type FnRegQueryValueW = unsafe extern "system" fn(HKEY, LPCWSTR, LPWSTR, PLONG) -> LSTATUS;
pub type FnRegRenameKey = unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR) -> LSTATUS;
pub type FnRegReplaceKeyA = unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR, LPCSTR) -> LSTATUS;
pub type FnRegReplaceKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR, LPCWSTR) -> LSTATUS;
pub type FnRegRestoreKeyA = unsafe extern "system" fn(HKEY, LPCSTR, DWORD) -> LSTATUS;
pub type FnRegRestoreKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, DWORD) -> LSTATUS;
pub type FnRegSaveKeyA = unsafe extern "system" fn(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES) -> LSTATUS;
pub type FnRegSaveKeyExA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES, DWORD) -> LSTATUS;
pub type FnRegSaveKeyExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES, DWORD) -> LSTATUS;
pub type FnRegSaveKeyW = unsafe extern "system" fn(HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES) -> LSTATUS;
pub type FnRegSetKeySecurity =
    unsafe extern "system" fn(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> LSTATUS;
pub type FnRegSetKeyValueA =
    unsafe extern "system" fn(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD) -> LSTATUS;
pub type FnRegSetKeyValueW =
    unsafe extern "system" fn(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD) -> LSTATUS;
pub type FnRegSetValueA = unsafe extern "system" fn(HKEY, LPCSTR, DWORD, LPCSTR, DWORD) -> LSTATUS;
pub type FnRegSetValueExA =
    unsafe extern "system" fn(HKEY, LPCSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegSetValueExW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, DWORD, *const BYTE, DWORD) -> LSTATUS;
pub type FnRegSetValueW =
    unsafe extern "system" fn(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD) -> LSTATUS;
pub type FnRegUnLoadKeyA = unsafe extern "system" fn(HKEY, LPCSTR) -> LSTATUS;
pub type FnRegUnLoadKeyW = unsafe extern "system" fn(HKEY, LPCWSTR) -> LSTATUS;
pub type FnRegisterEventSourceA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> HANDLE;
pub type FnRegisterEventSourceW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> HANDLE;
pub type FnRegisterServiceCtrlHandlerA =
    unsafe extern "system" fn(LPCSTR, LPHANDLER_FUNCTION) -> SERVICE_STATUS_HANDLE;
pub type FnRegisterServiceCtrlHandlerExA =
    unsafe extern "system" fn(LPCSTR, LPHANDLER_FUNCTION_EX, LPVOID) -> SERVICE_STATUS_HANDLE;
pub type FnRegisterServiceCtrlHandlerExW =
    unsafe extern "system" fn(LPCWSTR, LPHANDLER_FUNCTION_EX, LPVOID) -> SERVICE_STATUS_HANDLE;
pub type FnRegisterServiceCtrlHandlerW =
    unsafe extern "system" fn(LPCWSTR, LPHANDLER_FUNCTION) -> SERVICE_STATUS_HANDLE;
pub type FnRegisterTraceGuidsA = unsafe extern "system" fn(
    WMIDPREQUEST,
    PVOID,
    LPCGUID,
    ULONG,
    PTRACE_GUID_REGISTRATION,
    LPCSTR,
    LPCSTR,
    PTRACEHANDLE,
) -> ULONG;
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
pub type FnRegisterWaitChainCOMCallback =
    unsafe extern "system" fn(PCOGETCALLSTATE, PCOGETACTIVATIONSTATE) -> ();
pub type FnRemoveTraceCallback = unsafe extern "system" fn(LPCGUID) -> ULONG;
pub type FnRemoveUsersFromEncryptedFile =
    unsafe extern "system" fn(LPCWSTR, PENCRYPTION_CERTIFICATE_HASH_LIST) -> DWORD;
pub type FnReportEventA = unsafe extern "system" fn(
    HANDLE,
    WORD,
    WORD,
    DWORD,
    PSID,
    WORD,
    DWORD,
    *mut LPCSTR,
    LPVOID,
) -> BOOL;
pub type FnReportEventW = unsafe extern "system" fn(
    HANDLE,
    WORD,
    WORD,
    DWORD,
    PSID,
    WORD,
    DWORD,
    *mut LPCWSTR,
    LPVOID,
) -> BOOL;
pub type FnRevertToSelf = unsafe extern "system" fn() -> BOOL;
pub type FnSaferCloseLevel = unsafe extern "system" fn(SAFER_LEVEL_HANDLE) -> BOOL;
pub type FnSaferComputeTokenFromLevel =
    unsafe extern "system" fn(SAFER_LEVEL_HANDLE, HANDLE, PHANDLE, DWORD, LPVOID) -> BOOL;
pub type FnSaferCreateLevel =
    unsafe extern "system" fn(DWORD, DWORD, DWORD, *mut SAFER_LEVEL_HANDLE, LPVOID) -> BOOL;
pub type FnSaferGetLevelInformation = unsafe extern "system" fn(
    SAFER_LEVEL_HANDLE,
    SAFER_OBJECT_INFO_CLASS,
    LPVOID,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnSaferGetPolicyInformation =
    unsafe extern "system" fn(DWORD, SAFER_POLICY_INFO_CLASS, DWORD, PVOID, PDWORD, LPVOID) -> BOOL;
pub type FnSaferIdentifyLevel = unsafe extern "system" fn(
    DWORD,
    PSAFER_CODE_PROPERTIES,
    *mut SAFER_LEVEL_HANDLE,
    LPVOID,
) -> BOOL;
pub type FnSaferRecordEventLogEntry =
    unsafe extern "system" fn(SAFER_LEVEL_HANDLE, LPCWSTR, LPVOID) -> BOOL;
pub type FnSaferSetLevelInformation =
    unsafe extern "system" fn(SAFER_LEVEL_HANDLE, SAFER_OBJECT_INFO_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSaferSetPolicyInformation =
    unsafe extern "system" fn(DWORD, SAFER_POLICY_INFO_CLASS, DWORD, PVOID, LPVOID) -> BOOL;
pub type FnSaferiIsExecutableFileType = unsafe extern "system" fn(LPCWSTR, BOOLEAN) -> BOOL;
pub type FnSetAclInformation =
    unsafe extern "system" fn(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS) -> BOOL;
pub type FnSetEncryptedFileMetadata = unsafe extern "system" fn(
    LPCWSTR,
    PBYTE,
    PBYTE,
    PENCRYPTION_CERTIFICATE_HASH,
    DWORD,
    PENCRYPTION_CERTIFICATE_HASH_LIST,
) -> DWORD;
pub type FnSetEntriesInAclA =
    unsafe extern "system" fn(ULONG, PEXPLICIT_ACCESS_A, PACL, *mut PACL) -> DWORD;
pub type FnSetEntriesInAclW =
    unsafe extern "system" fn(ULONG, PEXPLICIT_ACCESS_W, PACL, *mut PACL) -> DWORD;
pub type FnSetFileSecurityW =
    unsafe extern "system" fn(LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetKernelObjectSecurity =
    unsafe extern "system" fn(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetNamedSecurityInfoA = unsafe extern "system" fn(
    LPSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
) -> DWORD;
pub type FnSetNamedSecurityInfoW = unsafe extern "system" fn(
    LPWSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
) -> DWORD;
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
pub type FnSetSecurityInfo = unsafe extern "system" fn(
    HANDLE,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
) -> DWORD;
pub type FnSetServiceBits =
    unsafe extern "system" fn(SERVICE_STATUS_HANDLE, DWORD, BOOL, BOOL) -> BOOL;
pub type FnSetServiceObjectSecurity =
    unsafe extern "system" fn(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetServiceStatus =
    unsafe extern "system" fn(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS) -> BOOL;
pub type FnSetThreadToken = unsafe extern "system" fn(PHANDLE, HANDLE) -> BOOL;
pub type FnSetTokenInformation =
    unsafe extern "system" fn(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD) -> BOOL;
pub type FnSetTraceCallback = unsafe extern "system" fn(LPCGUID, PEVENT_CALLBACK) -> ULONG;
pub type FnSetUserFileEncryptionKey = unsafe extern "system" fn(PENCRYPTION_CERTIFICATE) -> DWORD;
pub type FnSetUserFileEncryptionKeyEx =
    unsafe extern "system" fn(PENCRYPTION_CERTIFICATE, DWORD, DWORD, LPVOID) -> DWORD;
pub type FnStartServiceA = unsafe extern "system" fn(SC_HANDLE, DWORD, *mut LPCSTR) -> BOOL;
pub type FnStartServiceCtrlDispatcherA =
    unsafe extern "system" fn(*const SERVICE_TABLE_ENTRYA) -> BOOL;
pub type FnStartServiceCtrlDispatcherW =
    unsafe extern "system" fn(*const SERVICE_TABLE_ENTRYW) -> BOOL;
pub type FnStartServiceW = unsafe extern "system" fn(SC_HANDLE, DWORD, *mut LPCWSTR) -> BOOL;
pub type FnStartTraceA =
    unsafe extern "system" fn(PTRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnStartTraceW =
    unsafe extern "system" fn(PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnStopTraceA =
    unsafe extern "system" fn(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnStopTraceW =
    unsafe extern "system" fn(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnSystemFunction036 = unsafe extern "system" fn(PVOID, ULONG) -> BOOLEAN;
pub type FnSystemFunction040 = unsafe extern "system" fn(PVOID, ULONG, ULONG) -> NTSTATUS;
pub type FnSystemFunction041 = unsafe extern "system" fn(PVOID, ULONG, ULONG) -> NTSTATUS;
pub type FnTraceEvent = unsafe extern "system" fn(TRACEHANDLE, PEVENT_TRACE_HEADER) -> ULONG;
pub type FnTraceEventInstance = unsafe extern "system" fn(
    TRACEHANDLE,
    PEVENT_TRACE_HEADER,
    PEVENT_INSTANCE_INFO,
    PEVENT_INSTANCE_INFO,
) -> ULONG;
pub type FnTraceMessage = unsafe extern "system" fn(TRACEHANDLE, ULONG, LPGUID, USHORT) -> ULONG;
pub type FnTraceMessageVa =
    unsafe extern "system" fn(TRACEHANDLE, ULONG, LPGUID, USHORT, va_list) -> ();
pub type FnTraceQueryInformation =
    unsafe extern "system" fn(TRACEHANDLE, TRACE_QUERY_INFO_CLASS, PVOID, ULONG, PULONG) -> ULONG;
pub type FnTraceSetInformation =
    unsafe extern "system" fn(TRACEHANDLE, TRACE_INFO_CLASS, PVOID, ULONG) -> ULONG;
pub type FnTreeResetNamedSecurityInfoA = unsafe extern "system" fn(
    LPSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
    BOOL,
    FN_PROGRESS,
    PROG_INVOKE_SETTING,
    PVOID,
) -> DWORD;
pub type FnTreeResetNamedSecurityInfoW = unsafe extern "system" fn(
    LPWSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
    BOOL,
    FN_PROGRESS,
    PROG_INVOKE_SETTING,
    PVOID,
) -> DWORD;
pub type FnTreeSetNamedSecurityInfoA = unsafe extern "system" fn(
    LPSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
    DWORD,
    FN_PROGRESS,
    PROG_INVOKE_SETTING,
    PVOID,
) -> DWORD;
pub type FnTreeSetNamedSecurityInfoW = unsafe extern "system" fn(
    LPWSTR,
    SE_OBJECT_TYPE,
    SECURITY_INFORMATION,
    PSID,
    PSID,
    PACL,
    PACL,
    DWORD,
    FN_PROGRESS,
    PROG_INVOKE_SETTING,
    PVOID,
) -> DWORD;
pub type FnUninstallApplication = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnUnlockServiceDatabase = unsafe extern "system" fn(SC_LOCK) -> BOOL;
pub type FnUnregisterTraceGuids = unsafe extern "system" fn(TRACEHANDLE) -> ULONG;
pub type FnUpdateTraceA =
    unsafe extern "system" fn(TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnUpdateTraceW =
    unsafe extern "system" fn(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES) -> ULONG;
pub type FnWaitServiceState = unsafe extern "system" fn(SC_HANDLE, DWORD, DWORD, HANDLE) -> DWORD;
