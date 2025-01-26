use winapi::ctypes::{c_int, c_void};
use winapi::shared::bcrypt::BCRYPT_KEY_HANDLE;
use winapi::shared::guiddef::{GUID, LPCGUID};
use winapi::shared::minwindef::{
    BOOL, BYTE, DWORD, HMODULE, LPFILETIME, LPVOID, PBYTE, PDWORD, ULONG,
};
use winapi::shared::ntdef::{HANDLE, LONG, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PVOID, WCHAR};
use winapi::um::dpapi::CRYPTPROTECT_PROMPTSTRUCT;
use winapi::um::minwinbase::PSYSTEMTIME;
use winapi::um::mssip::{
    SIP_ADD_NEWPROVIDER, SIP_CAP_SET, SIP_DISPATCH_INFO, SIP_INDIRECT_DATA, SIP_SUBJECTINFO,
};
use winapi::um::ncrypt::{HCRYPTKEY, HCRYPTPROV};
use winapi::um::wincrypt::{
    ALG_ID, CERT_EXTENSION, CRYPT_ATTRIBUTE, CRYPT_DATA_BLOB, CRYPT_HASH_BLOB,
    CRYPT_OID_FUNC_ENTRY, CRYPT_PKCS8_IMPORT_PARAMS, CRYPT_TIMESTAMP_PARA, DATA_BLOB,
    HCERTCHAINENGINE, HCERTSTORE, HCERT_SERVER_OCSP_RESPONSE, HCRYPTASYNC, HCRYPTDEFAULTCONTEXT,
    HCRYPTMSG, HCRYPTOIDFUNCADDR, HCRYPTOIDFUNCSET, HCRYPTPROV_LEGACY,
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, PCCERT_CHAIN_CONTEXT, PCCERT_CONTEXT,
    PCCERT_SELECT_CHAIN_PARA, PCCERT_SELECT_CRITERIA, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT,
    PCCERT_STRONG_SIGN_PARA, PCCRL_CONTEXT, PCCRYPT_OID_INFO, PCCTL_CONTEXT,
    PCERT_CHAIN_ENGINE_CONFIG, PCERT_CHAIN_PARA, PCERT_CHAIN_POLICY_PARA,
    PCERT_CHAIN_POLICY_STATUS, PCERT_CREATE_CONTEXT_PARA, PCERT_ENHKEY_USAGE, PCERT_EXTENSION,
    PCERT_EXTENSIONS, PCERT_INFO, PCERT_NAME_BLOB, PCERT_NAME_INFO, PCERT_PHYSICAL_STORE_INFO,
    PCERT_PUBLIC_KEY_INFO, PCERT_RDN, PCERT_RDN_ATTR, PCERT_RDN_VALUE_BLOB, PCERT_REVOCATION_PARA,
    PCERT_REVOCATION_STATUS, PCERT_SYSTEM_STORE_INFO, PCMSG_SIGNED_ENCODE_INFO,
    PCMSG_SIGNER_ENCODE_INFO, PCMSG_STREAM_INFO, PCRL_ENTRY, PCRL_INFO,
    PCRYPT_ALGORITHM_IDENTIFIER, PCRYPT_ATTRIBUTE, PCRYPT_DATA_BLOB, PCRYPT_DECODE_PARA,
    PCRYPT_DECRYPT_MESSAGE_PARA, PCRYPT_DER_BLOB, PCRYPT_ENCODE_PARA, PCRYPT_ENCRYPT_MESSAGE_PARA,
    PCRYPT_HASH_MESSAGE_PARA, PCRYPT_INTEGER_BLOB, PCRYPT_KEY_PROV_INFO,
    PCRYPT_KEY_SIGN_MESSAGE_PARA, PCRYPT_KEY_VERIFY_MESSAGE_PARA, PCRYPT_SIGN_MESSAGE_PARA,
    PCRYPT_TIMESTAMP_CONTEXT, PCRYPT_VERIFY_MESSAGE_PARA, PCTL_ENTRY, PCTL_INFO, PCTL_USAGE,
    PCTL_VERIFY_USAGE_PARA, PCTL_VERIFY_USAGE_STATUS, PFN_CERT_ENUM_PHYSICAL_STORE,
    PFN_CERT_ENUM_SYSTEM_STORE, PFN_CERT_ENUM_SYSTEM_STORE_LOCATION,
    PFN_CRYPT_ASYNC_PARAM_FREE_FUNC, PFN_CRYPT_ENUM_KEYID_PROP, PFN_CRYPT_ENUM_OID_FUNC,
    PFN_CRYPT_ENUM_OID_INFO, PHCRYPTASYNC, PUBLICKEYSTRUC,
};
use winapi::um::winnt::PSID;

pub type FnCertAddCRLContextToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCRL_CONTEXT, DWORD, *mut PCCRL_CONTEXT) -> BOOL;
pub type FnCertAddCRLLinkToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCRL_CONTEXT, DWORD, *mut PCCRL_CONTEXT) -> BOOL;
pub type FnCertAddCTLContextToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCTL_CONTEXT, DWORD, *mut PCCTL_CONTEXT) -> BOOL;
pub type FnCertAddCTLLinkToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCTL_CONTEXT, DWORD, *mut PCCTL_CONTEXT) -> BOOL;
pub type FnCertAddCertificateContextToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCERT_CONTEXT, DWORD, *mut PCCERT_CONTEXT) -> BOOL;
pub type FnCertAddCertificateLinkToStore =
    unsafe extern "system" fn(HCERTSTORE, PCCERT_CONTEXT, DWORD, *mut PCCERT_CONTEXT) -> BOOL;
pub type FnCertAddEncodedCRLToStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    *mut PCCRL_CONTEXT,
) -> BOOL;
pub type FnCertAddEncodedCTLToStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    *mut PCCTL_CONTEXT,
) -> BOOL;
pub type FnCertAddEncodedCertificateToStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCertAddEncodedCertificateToSystemStoreA =
    unsafe extern "system" fn(LPCSTR, *const BYTE, DWORD) -> BOOL;
pub type FnCertAddEncodedCertificateToSystemStoreW =
    unsafe extern "system" fn(LPCWSTR, *const BYTE, DWORD) -> BOOL;
pub type FnCertAddEnhancedKeyUsageIdentifier =
    unsafe extern "system" fn(PCCERT_CONTEXT, LPCSTR) -> BOOL;
pub type FnCertAddRefServerOcspResponse =
    unsafe extern "system" fn(HCERT_SERVER_OCSP_RESPONSE) -> ();
pub type FnCertAddRefServerOcspResponseContext =
    unsafe extern "system" fn(PCCERT_SERVER_OCSP_RESPONSE_CONTEXT) -> ();
pub type FnCertAddSerializedElementToStore = unsafe extern "system" fn(
    HCERTSTORE,
    *const BYTE,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    *mut DWORD,
) -> BOOL;
pub type FnCertAddStoreToCollection =
    unsafe extern "system" fn(HCERTSTORE, HCERTSTORE, DWORD, DWORD) -> BOOL;
pub type FnCertAlgIdToOID = unsafe extern "system" fn(DWORD) -> LPCSTR;
pub type FnCertCloseServerOcspResponse =
    unsafe extern "system" fn(HCERT_SERVER_OCSP_RESPONSE, DWORD) -> ();
pub type FnCertCloseStore = unsafe extern "system" fn(HCERTSTORE, DWORD) -> BOOL;
pub type FnCertCompareCertificate =
    unsafe extern "system" fn(DWORD, PCERT_INFO, PCERT_INFO) -> BOOL;
pub type FnCertCompareCertificateName =
    unsafe extern "system" fn(DWORD, PCERT_NAME_BLOB, PCERT_NAME_BLOB) -> BOOL;
pub type FnCertCompareIntegerBlob =
    unsafe extern "system" fn(PCRYPT_INTEGER_BLOB, PCRYPT_INTEGER_BLOB) -> BOOL;
pub type FnCertComparePublicKeyInfo =
    unsafe extern "system" fn(DWORD, PCERT_PUBLIC_KEY_INFO, PCERT_PUBLIC_KEY_INFO) -> BOOL;
pub type FnCertControlStore =
    unsafe extern "system" fn(HCERTSTORE, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCertCreateCRLContext =
    unsafe extern "system" fn(DWORD, *const BYTE, DWORD) -> PCCRL_CONTEXT;
pub type FnCertCreateCTLContext =
    unsafe extern "system" fn(DWORD, *const BYTE, DWORD) -> PCCTL_CONTEXT;
pub type FnCertCreateCTLEntryFromCertificateContextProperties = unsafe extern "system" fn(
    PCCERT_CONTEXT,
    DWORD,
    PCRYPT_ATTRIBUTE,
    DWORD,
    *mut c_void,
    PCTL_ENTRY,
    *mut DWORD,
) -> BOOL;
pub type FnCertCreateCertificateChainEngine =
    unsafe extern "system" fn(PCERT_CHAIN_ENGINE_CONFIG, *mut HCERTCHAINENGINE) -> BOOL;
pub type FnCertCreateCertificateContext =
    unsafe extern "system" fn(DWORD, *const BYTE, DWORD) -> PCCERT_CONTEXT;
pub type FnCertCreateContext = unsafe extern "system" fn(
    DWORD,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    PCERT_CREATE_CONTEXT_PARA,
) -> ();
pub type FnCertCreateSelfSignCertificate = unsafe extern "system" fn(
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    PCERT_NAME_BLOB,
    DWORD,
    PCRYPT_KEY_PROV_INFO,
    PCRYPT_ALGORITHM_IDENTIFIER,
    PSYSTEMTIME,
    PSYSTEMTIME,
    PCERT_EXTENSIONS,
) -> PCCERT_CONTEXT;
pub type FnCertDeleteCRLFromStore = unsafe extern "system" fn(PCCRL_CONTEXT) -> BOOL;
pub type FnCertDeleteCTLFromStore = unsafe extern "system" fn(PCCTL_CONTEXT) -> BOOL;
pub type FnCertDeleteCertificateFromStore = unsafe extern "system" fn(PCCERT_CONTEXT) -> BOOL;
pub type FnCertDuplicateCRLContext = unsafe extern "system" fn(PCCRL_CONTEXT) -> PCCRL_CONTEXT;
pub type FnCertDuplicateCTLContext = unsafe extern "system" fn(PCCTL_CONTEXT) -> PCCTL_CONTEXT;
pub type FnCertDuplicateCertificateChain =
    unsafe extern "system" fn(PCCERT_CHAIN_CONTEXT) -> PCCERT_CHAIN_CONTEXT;
pub type FnCertDuplicateCertificateContext =
    unsafe extern "system" fn(PCCERT_CONTEXT) -> PCCERT_CONTEXT;
pub type FnCertDuplicateStore = unsafe extern "system" fn(HCERTSTORE) -> HCERTSTORE;
pub type FnCertEnumCRLContextProperties = unsafe extern "system" fn(PCCRL_CONTEXT, DWORD) -> DWORD;
pub type FnCertEnumCRLsInStore =
    unsafe extern "system" fn(HCERTSTORE, PCCRL_CONTEXT) -> PCCRL_CONTEXT;
pub type FnCertEnumCTLContextProperties = unsafe extern "system" fn(PCCTL_CONTEXT, DWORD) -> DWORD;
pub type FnCertEnumCTLsInStore =
    unsafe extern "system" fn(HCERTSTORE, PCCTL_CONTEXT) -> PCCTL_CONTEXT;
pub type FnCertEnumCertificateContextProperties =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD) -> DWORD;
pub type FnCertEnumCertificatesInStore =
    unsafe extern "system" fn(HCERTSTORE, PCCERT_CONTEXT) -> PCCERT_CONTEXT;
pub type FnCertEnumPhysicalStore = unsafe extern "system" fn(
    *const c_void,
    DWORD,
    *mut c_void,
    PFN_CERT_ENUM_PHYSICAL_STORE,
) -> BOOL;
pub type FnCertEnumSubjectInSortedCTL =
    unsafe extern "system" fn(PCCTL_CONTEXT, PCRYPT_DER_BLOB, PCRYPT_DER_BLOB) -> BOOL;
pub type FnCertEnumSystemStore =
    unsafe extern "system" fn(DWORD, *mut c_void, *mut c_void, PFN_CERT_ENUM_SYSTEM_STORE) -> BOOL;
pub type FnCertEnumSystemStoreLocation =
    unsafe extern "system" fn(DWORD, *mut c_void, PFN_CERT_ENUM_SYSTEM_STORE_LOCATION) -> BOOL;
pub type FnCertFindAttribute =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut CRYPT_ATTRIBUTE) -> PCRYPT_ATTRIBUTE;
pub type FnCertFindCRLInStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    DWORD,
    DWORD,
    *const c_void,
    PCCRL_CONTEXT,
) -> PCCRL_CONTEXT;
pub type FnCertFindCTLInStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    DWORD,
    DWORD,
    *const c_void,
    PCCTL_CONTEXT,
) -> PCCTL_CONTEXT;
pub type FnCertFindCertificateInCRL = unsafe extern "system" fn(
    PCCERT_CONTEXT,
    PCCRL_CONTEXT,
    DWORD,
    *mut c_void,
    *mut PCRL_ENTRY,
) -> BOOL;
pub type FnCertFindCertificateInStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    DWORD,
    DWORD,
    *const c_void,
    PCCERT_CONTEXT,
) -> PCCERT_CONTEXT;
pub type FnCertFindChainInStore = unsafe extern "system" fn(
    HCERTSTORE,
    DWORD,
    DWORD,
    DWORD,
    *const c_void,
    PCCERT_CHAIN_CONTEXT,
) -> PCCERT_CHAIN_CONTEXT;
pub type FnCertFindExtension =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut CERT_EXTENSION) -> PCERT_EXTENSION;
pub type FnCertFindRDNAttr = unsafe extern "system" fn(LPCSTR, PCERT_NAME_INFO) -> PCERT_RDN_ATTR;
pub type FnCertFindSubjectInCTL =
    unsafe extern "system" fn(DWORD, DWORD, *mut c_void, PCCTL_CONTEXT, DWORD) -> PCTL_ENTRY;
pub type FnCertFindSubjectInSortedCTL = unsafe extern "system" fn(
    PCRYPT_DATA_BLOB,
    PCCTL_CONTEXT,
    DWORD,
    *mut c_void,
    PCRYPT_DER_BLOB,
) -> BOOL;
pub type FnCertFreeCRLContext = unsafe extern "system" fn(PCCRL_CONTEXT) -> BOOL;
pub type FnCertFreeCTLContext = unsafe extern "system" fn(PCCTL_CONTEXT) -> BOOL;
pub type FnCertFreeCertificateChain = unsafe extern "system" fn(PCCERT_CHAIN_CONTEXT) -> ();
pub type FnCertFreeCertificateChainEngine = unsafe extern "system" fn(HCERTCHAINENGINE) -> ();
pub type FnCertFreeCertificateChainList =
    unsafe extern "system" fn(*mut PCCERT_CHAIN_CONTEXT) -> ();
pub type FnCertFreeCertificateContext = unsafe extern "system" fn(PCCERT_CONTEXT) -> BOOL;
pub type FnCertFreeServerOcspResponseContext =
    unsafe extern "system" fn(PCCERT_SERVER_OCSP_RESPONSE_CONTEXT) -> ();
pub type FnCertGetCRLContextProperty =
    unsafe extern "system" fn(PCCRL_CONTEXT, DWORD, *mut c_void, *mut DWORD) -> BOOL;
pub type FnCertGetCRLFromStore = unsafe extern "system" fn(
    HCERTSTORE,
    PCCERT_CONTEXT,
    PCCRL_CONTEXT,
    *mut DWORD,
) -> PCCRL_CONTEXT;
pub type FnCertGetCTLContextProperty =
    unsafe extern "system" fn(PCCTL_CONTEXT, DWORD, *mut c_void, *mut DWORD) -> BOOL;
pub type FnCertGetCertificateChain = unsafe extern "system" fn(
    HCERTCHAINENGINE,
    PCCERT_CONTEXT,
    LPFILETIME,
    HCERTSTORE,
    PCERT_CHAIN_PARA,
    DWORD,
    LPVOID,
    *mut PCCERT_CHAIN_CONTEXT,
) -> BOOL;
pub type FnCertGetCertificateContextProperty =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, *mut c_void, *mut DWORD) -> BOOL;
pub type FnCertGetEnhancedKeyUsage =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, PCERT_ENHKEY_USAGE, *mut DWORD) -> BOOL;
pub type FnCertGetIntendedKeyUsage =
    unsafe extern "system" fn(DWORD, PCERT_INFO, *mut BYTE, DWORD) -> BOOL;
pub type FnCertGetIssuerCertificateFromStore = unsafe extern "system" fn(
    HCERTSTORE,
    PCCERT_CONTEXT,
    PCCERT_CONTEXT,
    *mut DWORD,
) -> PCCERT_CONTEXT;
pub type FnCertGetNameStringA =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, DWORD, *mut c_void, LPSTR, DWORD) -> DWORD;
pub type FnCertGetNameStringW =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, DWORD, *mut c_void, LPWSTR, DWORD) -> DWORD;
pub type FnCertGetPublicKeyLength =
    unsafe extern "system" fn(DWORD, PCERT_PUBLIC_KEY_INFO) -> DWORD;
pub type FnCertGetServerOcspResponseContext =
    unsafe extern "system" fn(
        HCERT_SERVER_OCSP_RESPONSE,
        DWORD,
        LPVOID,
    ) -> PCCERT_SERVER_OCSP_RESPONSE_CONTEXT;
pub type FnCertGetStoreProperty =
    unsafe extern "system" fn(HCERTSTORE, DWORD, *mut c_void, *mut DWORD) -> BOOL;
pub type FnCertGetSubjectCertificateFromStore =
    unsafe extern "system" fn(HCERTSTORE, DWORD, PCERT_INFO) -> PCCERT_CONTEXT;
pub type FnCertGetValidUsages = unsafe extern "system" fn(
    DWORD,
    *mut PCCERT_CONTEXT,
    *mut c_int,
    *mut LPSTR,
    *mut DWORD,
) -> BOOL;
pub type FnCertIsRDNAttrsInCertificateName =
    unsafe extern "system" fn(DWORD, DWORD, PCERT_NAME_BLOB, PCERT_RDN) -> BOOL;
pub type FnCertIsStrongHashToSign =
    unsafe extern "system" fn(PCCERT_STRONG_SIGN_PARA, LPCWSTR, PCCERT_CONTEXT) -> BOOL;
pub type FnCertIsValidCRLForCertificate =
    unsafe extern "system" fn(PCCERT_CONTEXT, PCCRL_CONTEXT, DWORD, *mut c_void) -> BOOL;
pub type FnCertIsWeakHash = unsafe extern "system" fn(
    DWORD,
    LPCWSTR,
    DWORD,
    PCCERT_CHAIN_CONTEXT,
    LPFILETIME,
    LPCWSTR,
) -> BOOL;
pub type FnCertNameToStrA =
    unsafe extern "system" fn(DWORD, PCERT_NAME_BLOB, DWORD, LPSTR, DWORD) -> DWORD;
pub type FnCertNameToStrW =
    unsafe extern "system" fn(DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD) -> DWORD;
pub type FnCertOIDToAlgId = unsafe extern "system" fn(LPCSTR) -> DWORD;
pub type FnCertOpenServerOcspResponse =
    unsafe extern "system" fn(PCCERT_CHAIN_CONTEXT, DWORD, LPVOID) -> HCERT_SERVER_OCSP_RESPONSE;
pub type FnCertOpenStore =
    unsafe extern "system" fn(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, *const c_void) -> HCERTSTORE;
pub type FnCertOpenSystemStoreA =
    unsafe extern "system" fn(HCRYPTPROV_LEGACY, LPCSTR) -> HCERTSTORE;
pub type FnCertOpenSystemStoreW =
    unsafe extern "system" fn(HCRYPTPROV_LEGACY, LPCWSTR) -> HCERTSTORE;
pub type FnCertRDNValueToStrA =
    unsafe extern "system" fn(DWORD, PCERT_RDN_VALUE_BLOB, LPSTR, DWORD) -> DWORD;
pub type FnCertRDNValueToStrW =
    unsafe extern "system" fn(DWORD, PCERT_RDN_VALUE_BLOB, LPWSTR, DWORD) -> DWORD;
pub type FnCertRegisterPhysicalStore = unsafe extern "system" fn(
    *const c_void,
    DWORD,
    LPCWSTR,
    PCERT_PHYSICAL_STORE_INFO,
    *mut c_void,
) -> BOOL;
pub type FnCertRegisterSystemStore =
    unsafe extern "system" fn(*const c_void, DWORD, PCERT_SYSTEM_STORE_INFO, *mut c_void) -> BOOL;
pub type FnCertRemoveEnhancedKeyUsageIdentifier =
    unsafe extern "system" fn(PCCERT_CONTEXT, LPCSTR) -> BOOL;
pub type FnCertRemoveStoreFromCollection = unsafe extern "system" fn(HCERTSTORE, HCERTSTORE) -> ();
pub type FnCertResyncCertificateChainEngine = unsafe extern "system" fn(HCERTCHAINENGINE) -> BOOL;
pub type FnCertRetrieveLogoOrBiometricInfo = unsafe extern "system" fn(
    PCCERT_CONTEXT,
    LPCSTR,
    DWORD,
    DWORD,
    DWORD,
    *mut c_void,
    *mut DWORD,
    *mut LPWSTR,
) -> BOOL;
pub type FnCertSaveStore =
    unsafe extern "system" fn(HCERTSTORE, DWORD, DWORD, DWORD, *mut c_void, DWORD) -> BOOL;
pub type FnCertSelectCertificateChains = unsafe extern "system" fn(
    LPCGUID,
    DWORD,
    PCCERT_SELECT_CHAIN_PARA,
    DWORD,
    PCCERT_SELECT_CRITERIA,
    HCERTSTORE,
    PDWORD,
) -> BOOL;
pub type FnCertSerializeCRLStoreElement =
    unsafe extern "system" fn(PCCRL_CONTEXT, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCertSerializeCTLStoreElement =
    unsafe extern "system" fn(PCCTL_CONTEXT, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCertSerializeCertificateStoreElement =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCertSetCRLContextProperty =
    unsafe extern "system" fn(PCCRL_CONTEXT, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCertSetCTLContextProperty =
    unsafe extern "system" fn(PCCTL_CONTEXT, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCertSetCertificateContextPropertiesFromCTLEntry =
    unsafe extern "system" fn(PCCERT_CONTEXT, PCTL_ENTRY, DWORD) -> BOOL;
pub type FnCertSetCertificateContextProperty =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCertSetEnhancedKeyUsage =
    unsafe extern "system" fn(PCCERT_CONTEXT, PCERT_ENHKEY_USAGE) -> BOOL;
pub type FnCertSetStoreProperty =
    unsafe extern "system" fn(HCERTSTORE, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCertStrToNameA = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    DWORD,
    *mut c_void,
    *mut BYTE,
    *mut DWORD,
    *mut LPCSTR,
) -> BOOL;
pub type FnCertStrToNameW = unsafe extern "system" fn(
    DWORD,
    LPCWSTR,
    DWORD,
    *mut c_void,
    *mut BYTE,
    *mut DWORD,
    *mut LPCWSTR,
) -> BOOL;
pub type FnCertUnregisterPhysicalStore =
    unsafe extern "system" fn(*const c_void, DWORD, LPCWSTR) -> BOOL;
pub type FnCertUnregisterSystemStore = unsafe extern "system" fn(*const c_void, DWORD) -> BOOL;
pub type FnCertVerifyCRLRevocation =
    unsafe extern "system" fn(DWORD, PCERT_INFO, DWORD, *mut PCRL_INFO) -> BOOL;
pub type FnCertVerifyCRLTimeValidity = unsafe extern "system" fn(LPFILETIME, PCRL_INFO) -> LONG;
pub type FnCertVerifyCTLUsage = unsafe extern "system" fn(
    DWORD,
    DWORD,
    *mut c_void,
    PCTL_USAGE,
    DWORD,
    PCTL_VERIFY_USAGE_PARA,
    PCTL_VERIFY_USAGE_STATUS,
) -> BOOL;
pub type FnCertVerifyCertificateChainPolicy = unsafe extern "system" fn(
    LPCSTR,
    PCCERT_CHAIN_CONTEXT,
    PCERT_CHAIN_POLICY_PARA,
    PCERT_CHAIN_POLICY_STATUS,
) -> BOOL;
pub type FnCertVerifyRevocation = unsafe extern "system" fn(
    DWORD,
    DWORD,
    DWORD,
    *mut PVOID,
    DWORD,
    PCERT_REVOCATION_PARA,
    PCERT_REVOCATION_STATUS,
) -> BOOL;
pub type FnCertVerifySubjectCertificateContext =
    unsafe extern "system" fn(PCCERT_CONTEXT, PCCERT_CONTEXT, *mut DWORD) -> BOOL;
pub type FnCertVerifyTimeValidity = unsafe extern "system" fn(LPFILETIME, PCERT_INFO) -> LONG;
pub type FnCertVerifyValidityNesting = unsafe extern "system" fn(PCERT_INFO, PCERT_INFO) -> BOOL;
pub type FnCryptAcquireCertificatePrivateKey = unsafe extern "system" fn(
    PCCERT_CONTEXT,
    DWORD,
    *mut c_void,
    *mut HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    *mut DWORD,
    *mut BOOL,
) -> BOOL;
pub type FnCryptBinaryToStringA =
    unsafe extern "system" fn(*const BYTE, DWORD, DWORD, LPSTR, *mut DWORD) -> BOOL;
pub type FnCryptBinaryToStringW =
    unsafe extern "system" fn(*const BYTE, DWORD, DWORD, LPWSTR, *mut DWORD) -> BOOL;
pub type FnCryptCloseAsyncHandle = unsafe extern "system" fn(HCRYPTASYNC) -> BOOL;
pub type FnCryptCreateAsyncHandle = unsafe extern "system" fn(DWORD, PHCRYPTASYNC) -> BOOL;
pub type FnCryptCreateKeyIdentifierFromCSP = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    *const PUBLICKEYSTRUC,
    DWORD,
    DWORD,
    *mut c_void,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptDecodeMessage = unsafe extern "system" fn(
    DWORD,
    PCRYPT_DECRYPT_MESSAGE_PARA,
    PCRYPT_VERIFY_MESSAGE_PARA,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    *mut DWORD,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut PCCERT_CONTEXT,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCryptDecodeObject = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    *const BYTE,
    DWORD,
    DWORD,
    *mut c_void,
    *mut DWORD,
) -> BOOL;
pub type FnCryptDecodeObjectEx = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    *const BYTE,
    DWORD,
    DWORD,
    PCRYPT_DECODE_PARA,
    *mut c_void,
    *mut DWORD,
) -> BOOL;
pub type FnCryptDecryptAndVerifyMessageSignature = unsafe extern "system" fn(
    PCRYPT_DECRYPT_MESSAGE_PARA,
    PCRYPT_VERIFY_MESSAGE_PARA,
    DWORD,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut PCCERT_CONTEXT,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCryptDecryptMessage = unsafe extern "system" fn(
    PCRYPT_DECRYPT_MESSAGE_PARA,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCryptEncodeObject =
    unsafe extern "system" fn(DWORD, LPCSTR, *const c_void, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnCryptEncodeObjectEx = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    *const c_void,
    DWORD,
    PCRYPT_ENCODE_PARA,
    *mut c_void,
    *mut DWORD,
) -> BOOL;
pub type FnCryptEncryptMessage = unsafe extern "system" fn(
    PCRYPT_ENCRYPT_MESSAGE_PARA,
    DWORD,
    *mut PCCERT_CONTEXT,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptEnumKeyIdentifierProperties = unsafe extern "system" fn(
    *const CRYPT_HASH_BLOB,
    DWORD,
    DWORD,
    LPCWSTR,
    *mut c_void,
    *mut c_void,
    PFN_CRYPT_ENUM_KEYID_PROP,
) -> BOOL;
pub type FnCryptEnumOIDFunction = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    LPCSTR,
    DWORD,
    *mut c_void,
    PFN_CRYPT_ENUM_OID_FUNC,
) -> BOOL;
pub type FnCryptEnumOIDInfo =
    unsafe extern "system" fn(DWORD, DWORD, *mut c_void, PFN_CRYPT_ENUM_OID_INFO) -> BOOL;
pub type FnCryptExportPKCS8 = unsafe extern "system" fn(
    HCRYPTPROV,
    DWORD,
    LPSTR,
    DWORD,
    *mut c_void,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptExportPublicKeyInfo = unsafe extern "system" fn(
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    DWORD,
    DWORD,
    PCERT_PUBLIC_KEY_INFO,
    *mut DWORD,
) -> BOOL;
pub type FnCryptExportPublicKeyInfoEx = unsafe extern "system" fn(
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    DWORD,
    DWORD,
    LPSTR,
    DWORD,
    *mut c_void,
    PCERT_PUBLIC_KEY_INFO,
    *mut DWORD,
) -> BOOL;
pub type FnCryptExportPublicKeyInfoFromBCryptKeyHandle = unsafe extern "system" fn(
    BCRYPT_KEY_HANDLE,
    DWORD,
    LPSTR,
    DWORD,
    *mut c_void,
    PCERT_PUBLIC_KEY_INFO,
    *mut DWORD,
) -> BOOL;
pub type FnCryptFindCertificateKeyProvInfo =
    unsafe extern "system" fn(PCCERT_CONTEXT, DWORD, *mut c_void) -> BOOL;
pub type FnCryptFindLocalizedName = unsafe extern "system" fn(LPCWSTR) -> LPCWSTR;
pub type FnCryptFindOIDInfo =
    unsafe extern "system" fn(DWORD, *mut c_void, DWORD) -> PCCRYPT_OID_INFO;
pub type FnCryptFormatObject = unsafe extern "system" fn(
    DWORD,
    DWORD,
    DWORD,
    *mut c_void,
    LPCSTR,
    *const BYTE,
    DWORD,
    *mut c_void,
    *mut DWORD,
) -> BOOL;
pub type FnCryptFreeOIDFunctionAddress =
    unsafe extern "system" fn(HCRYPTOIDFUNCADDR, DWORD) -> BOOL;
pub type FnCryptGetAsyncParam = unsafe extern "system" fn(
    HCRYPTASYNC,
    LPSTR,
    *mut LPVOID,
    *mut PFN_CRYPT_ASYNC_PARAM_FREE_FUNC,
) -> BOOL;
pub type FnCryptGetDefaultOIDDllList =
    unsafe extern "system" fn(HCRYPTOIDFUNCSET, DWORD, *mut WCHAR, *mut DWORD) -> BOOL;
pub type FnCryptGetDefaultOIDFunctionAddress = unsafe extern "system" fn(
    HCRYPTOIDFUNCSET,
    DWORD,
    LPCWSTR,
    DWORD,
    *mut HCRYPTOIDFUNCADDR,
) -> BOOL;
pub type FnCryptGetKeyIdentifierProperty = unsafe extern "system" fn(
    *const CRYPT_HASH_BLOB,
    DWORD,
    DWORD,
    LPCWSTR,
    *mut c_void,
    *mut c_void,
    *mut DWORD,
) -> BOOL;
pub type FnCryptGetMessageCertificates =
    unsafe extern "system" fn(DWORD, HCRYPTPROV_LEGACY, DWORD, *const BYTE, DWORD) -> HCERTSTORE;
pub type FnCryptGetMessageSignerCount =
    unsafe extern "system" fn(DWORD, *const BYTE, DWORD) -> LONG;
pub type FnCryptGetOIDFunctionAddress = unsafe extern "system" fn(
    HCRYPTOIDFUNCSET,
    DWORD,
    LPCSTR,
    DWORD,
    *mut HCRYPTOIDFUNCADDR,
) -> BOOL;
pub type FnCryptGetOIDFunctionValue = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    LPCSTR,
    LPCWSTR,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptHashCertificate = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    ALG_ID,
    DWORD,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptHashCertificate2 = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    *mut c_void,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptHashMessage = unsafe extern "system" fn(
    PCRYPT_HASH_MESSAGE_PARA,
    BOOL,
    DWORD,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptHashPublicKeyInfo = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    ALG_ID,
    DWORD,
    DWORD,
    PCERT_PUBLIC_KEY_INFO,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptHashToBeSigned = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    DWORD,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptImportPKCS8 = unsafe extern "system" fn(
    CRYPT_PKCS8_IMPORT_PARAMS,
    DWORD,
    *mut HCRYPTPROV,
    *mut c_void,
) -> BOOL;
pub type FnCryptImportPublicKeyInfo =
    unsafe extern "system" fn(HCRYPTPROV, DWORD, PCERT_PUBLIC_KEY_INFO, *mut HCRYPTKEY) -> BOOL;
pub type FnCryptImportPublicKeyInfoEx = unsafe extern "system" fn(
    HCRYPTPROV,
    DWORD,
    PCERT_PUBLIC_KEY_INFO,
    ALG_ID,
    DWORD,
    *mut c_void,
    *mut HCRYPTKEY,
) -> BOOL;
pub type FnCryptImportPublicKeyInfoEx2 = unsafe extern "system" fn(
    DWORD,
    PCERT_PUBLIC_KEY_INFO,
    DWORD,
    *mut c_void,
    *mut BCRYPT_KEY_HANDLE,
) -> BOOL;
pub type FnCryptInitOIDFunctionSet = unsafe extern "system" fn(LPCSTR, DWORD) -> HCRYPTOIDFUNCSET;
pub type FnCryptInstallDefaultContext = unsafe extern "system" fn(
    HCRYPTPROV,
    DWORD,
    *const c_void,
    DWORD,
    *mut c_void,
    *mut HCRYPTDEFAULTCONTEXT,
) -> BOOL;
pub type FnCryptInstallOIDFunctionAddress = unsafe extern "system" fn(
    HMODULE,
    DWORD,
    LPCSTR,
    DWORD,
    *const CRYPT_OID_FUNC_ENTRY,
    DWORD,
) -> BOOL;
pub type FnCryptMemAlloc = unsafe extern "system" fn(ULONG) -> LPVOID;
pub type FnCryptMemFree = unsafe extern "system" fn(LPVOID) -> ();
pub type FnCryptMemRealloc = unsafe extern "system" fn(LPVOID, ULONG) -> LPVOID;
pub type FnCryptMsgCalculateEncodedLength =
    unsafe extern "system" fn(DWORD, DWORD, DWORD, *const c_void, LPSTR, DWORD) -> DWORD;
pub type FnCryptMsgClose = unsafe extern "system" fn(HCRYPTMSG) -> BOOL;
pub type FnCryptMsgControl =
    unsafe extern "system" fn(HCRYPTMSG, DWORD, DWORD, *const c_void) -> BOOL;
pub type FnCryptMsgCountersign =
    unsafe extern "system" fn(HCRYPTMSG, DWORD, DWORD, PCMSG_SIGNER_ENCODE_INFO) -> BOOL;
pub type FnCryptMsgCountersignEncoded = unsafe extern "system" fn(
    DWORD,
    PBYTE,
    DWORD,
    DWORD,
    PCMSG_SIGNER_ENCODE_INFO,
    PBYTE,
    PDWORD,
) -> BOOL;
pub type FnCryptMsgDuplicate = unsafe extern "system" fn(HCRYPTMSG) -> HCRYPTMSG;
pub type FnCryptMsgEncodeAndSignCTL = unsafe extern "system" fn(
    DWORD,
    PCTL_INFO,
    PCMSG_SIGNED_ENCODE_INFO,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptMsgGetAndVerifySigner = unsafe extern "system" fn(
    HCRYPTMSG,
    DWORD,
    *mut HCERTSTORE,
    DWORD,
    *mut PCCERT_CONTEXT,
    *mut DWORD,
) -> BOOL;
pub type FnCryptMsgGetParam =
    unsafe extern "system" fn(HCRYPTMSG, DWORD, DWORD, *mut c_void, *mut DWORD) -> BOOL;
pub type FnCryptMsgOpenToDecode = unsafe extern "system" fn(
    DWORD,
    DWORD,
    DWORD,
    HCRYPTPROV_LEGACY,
    PCERT_INFO,
    PCMSG_STREAM_INFO,
) -> HCRYPTMSG;
pub type FnCryptMsgOpenToEncode = unsafe extern "system" fn(
    DWORD,
    DWORD,
    DWORD,
    *mut c_void,
    LPSTR,
    PCMSG_STREAM_INFO,
) -> HCRYPTMSG;
pub type FnCryptMsgSignCTL = unsafe extern "system" fn(
    DWORD,
    *mut BYTE,
    DWORD,
    PCMSG_SIGNED_ENCODE_INFO,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptMsgUpdate = unsafe extern "system" fn(HCRYPTMSG, *const BYTE, DWORD, BOOL) -> BOOL;
pub type FnCryptMsgVerifyCountersignatureEncoded = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    DWORD,
    PBYTE,
    DWORD,
    PBYTE,
    DWORD,
    PCERT_INFO,
) -> BOOL;
pub type FnCryptMsgVerifyCountersignatureEncodedEx = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    DWORD,
    PBYTE,
    DWORD,
    PBYTE,
    DWORD,
    DWORD,
    *mut c_void,
    DWORD,
    *mut c_void,
) -> BOOL;
pub type FnCryptProtectData = unsafe extern "system" fn(
    *mut DATA_BLOB,
    LPCWSTR,
    *mut DATA_BLOB,
    PVOID,
    *mut CRYPTPROTECT_PROMPTSTRUCT,
    DWORD,
    *mut DATA_BLOB,
) -> BOOL;
pub type FnCryptProtectMemory = unsafe extern "system" fn(LPVOID, DWORD, DWORD) -> BOOL;
pub type FnCryptQueryObject = unsafe extern "system" fn(
    DWORD,
    *const c_void,
    DWORD,
    DWORD,
    DWORD,
    *mut DWORD,
    *mut DWORD,
    *mut DWORD,
    *mut HCERTSTORE,
    *mut HCRYPTMSG,
) -> BOOL;
pub type FnCryptRegisterDefaultOIDFunction =
    unsafe extern "system" fn(DWORD, LPCSTR, DWORD, LPCWSTR) -> BOOL;
pub type FnCryptRegisterOIDFunction =
    unsafe extern "system" fn(DWORD, LPCSTR, LPCSTR, LPCWSTR, LPCSTR) -> BOOL;
pub type FnCryptRegisterOIDInfo = unsafe extern "system" fn(PCCRYPT_OID_INFO, DWORD) -> BOOL;
pub type FnCryptRetrieveTimeStamp = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    LPCSTR,
    *const CRYPT_TIMESTAMP_PARA,
    *const BYTE,
    DWORD,
    *mut PCRYPT_TIMESTAMP_CONTEXT,
    *mut PCCERT_CONTEXT,
    *mut HCERTSTORE,
) -> BOOL;
pub type FnCryptSIPAddProvider = unsafe extern "system" fn(*mut SIP_ADD_NEWPROVIDER) -> BOOL;
pub type FnCryptSIPCreateIndirectData =
    unsafe extern "system" fn(*mut SIP_SUBJECTINFO, *mut DWORD, *mut SIP_INDIRECT_DATA) -> BOOL;
pub type FnCryptSIPGetCaps =
    unsafe extern "system" fn(*mut SIP_SUBJECTINFO, *mut SIP_CAP_SET) -> BOOL;
pub type FnCryptSIPGetSealedDigest = unsafe extern "system" fn(
    *mut SIP_SUBJECTINFO,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptSIPGetSignedDataMsg = unsafe extern "system" fn(
    *mut SIP_SUBJECTINFO,
    *mut DWORD,
    DWORD,
    *mut DWORD,
    *mut BYTE,
) -> BOOL;
pub type FnCryptSIPLoad =
    unsafe extern "system" fn(*const GUID, DWORD, *mut SIP_DISPATCH_INFO) -> BOOL;
pub type FnCryptSIPPutSignedDataMsg =
    unsafe extern "system" fn(*mut SIP_SUBJECTINFO, DWORD, *mut DWORD, DWORD, *mut BYTE) -> BOOL;
pub type FnCryptSIPRemoveProvider = unsafe extern "system" fn(*mut GUID) -> BOOL;
pub type FnCryptSIPRemoveSignedDataMsg =
    unsafe extern "system" fn(*mut SIP_SUBJECTINFO, DWORD) -> BOOL;
pub type FnCryptSIPRetrieveSubjectGuid =
    unsafe extern "system" fn(LPCWSTR, HANDLE, *mut GUID) -> BOOL;
pub type FnCryptSIPRetrieveSubjectGuidForCatalogFile =
    unsafe extern "system" fn(LPCWSTR, HANDLE, *mut GUID) -> BOOL;
pub type FnCryptSIPVerifyIndirectData =
    unsafe extern "system" fn(*mut SIP_SUBJECTINFO, *mut SIP_INDIRECT_DATA) -> BOOL;
pub type FnCryptSetAsyncParam =
    unsafe extern "system" fn(HCRYPTASYNC, LPSTR, LPVOID, PFN_CRYPT_ASYNC_PARAM_FREE_FUNC) -> BOOL;
pub type FnCryptSetKeyIdentifierProperty = unsafe extern "system" fn(
    *const CRYPT_HASH_BLOB,
    DWORD,
    DWORD,
    LPCWSTR,
    *mut c_void,
    *const c_void,
) -> BOOL;
pub type FnCryptSetOIDFunctionValue =
    unsafe extern "system" fn(DWORD, LPCSTR, LPCSTR, LPCWSTR, DWORD, *const BYTE, DWORD) -> BOOL;
pub type FnCryptSignAndEncodeCertificate = unsafe extern "system" fn(
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    DWORD,
    DWORD,
    LPCSTR,
    *const c_void,
    PCRYPT_ALGORITHM_IDENTIFIER,
    *const c_void,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptSignAndEncryptMessage = unsafe extern "system" fn(
    PCRYPT_SIGN_MESSAGE_PARA,
    PCRYPT_ENCRYPT_MESSAGE_PARA,
    DWORD,
    *mut PCCERT_CONTEXT,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptSignCertificate = unsafe extern "system" fn(
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    DWORD,
    DWORD,
    *const BYTE,
    DWORD,
    PCRYPT_ALGORITHM_IDENTIFIER,
    *const c_void,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptSignMessage = unsafe extern "system" fn(
    PCRYPT_SIGN_MESSAGE_PARA,
    BOOL,
    DWORD,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptSignMessageWithKey = unsafe extern "system" fn(
    PCRYPT_KEY_SIGN_MESSAGE_PARA,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptStringToBinaryA = unsafe extern "system" fn(
    LPCSTR,
    DWORD,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut DWORD,
    *mut DWORD,
) -> BOOL;
pub type FnCryptStringToBinaryW = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut DWORD,
    *mut DWORD,
) -> BOOL;
pub type FnCryptUninstallDefaultContext =
    unsafe extern "system" fn(HCRYPTDEFAULTCONTEXT, DWORD, *mut c_void) -> BOOL;
pub type FnCryptUnprotectData = unsafe extern "system" fn(
    *mut DATA_BLOB,
    *mut LPWSTR,
    *mut DATA_BLOB,
    PVOID,
    *mut CRYPTPROTECT_PROMPTSTRUCT,
    DWORD,
    *mut DATA_BLOB,
) -> BOOL;
pub type FnCryptUnprotectMemory = unsafe extern "system" fn(LPVOID, DWORD, DWORD) -> BOOL;
pub type FnCryptUnregisterDefaultOIDFunction =
    unsafe extern "system" fn(DWORD, LPCSTR, LPCWSTR) -> BOOL;
pub type FnCryptUnregisterOIDFunction = unsafe extern "system" fn(DWORD, LPCSTR, LPCSTR) -> BOOL;
pub type FnCryptUnregisterOIDInfo = unsafe extern "system" fn(PCCRYPT_OID_INFO) -> BOOL;
pub type FnCryptUpdateProtectedState =
    unsafe extern "system" fn(PSID, LPCWSTR, DWORD, *mut DWORD, *mut DWORD) -> BOOL;
pub type FnCryptVerifyCertificateSignature = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    DWORD,
    *const BYTE,
    DWORD,
    PCERT_PUBLIC_KEY_INFO,
) -> BOOL;
pub type FnCryptVerifyCertificateSignatureEx = unsafe extern "system" fn(
    HCRYPTPROV_LEGACY,
    DWORD,
    DWORD,
    *mut c_void,
    DWORD,
    *mut c_void,
    DWORD,
    *mut c_void,
) -> BOOL;
pub type FnCryptVerifyDetachedMessageHash = unsafe extern "system" fn(
    PCRYPT_HASH_MESSAGE_PARA,
    *mut BYTE,
    DWORD,
    DWORD,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptVerifyDetachedMessageSignature = unsafe extern "system" fn(
    PCRYPT_VERIFY_MESSAGE_PARA,
    DWORD,
    *const BYTE,
    DWORD,
    DWORD,
    *mut DWORD,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCryptVerifyMessageHash = unsafe extern "system" fn(
    PCRYPT_HASH_MESSAGE_PARA,
    *mut BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptVerifyMessageSignature = unsafe extern "system" fn(
    PCRYPT_VERIFY_MESSAGE_PARA,
    DWORD,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
    *mut PCCERT_CONTEXT,
) -> BOOL;
pub type FnCryptVerifyMessageSignatureWithKey = unsafe extern "system" fn(
    PCRYPT_KEY_VERIFY_MESSAGE_PARA,
    PCERT_PUBLIC_KEY_INFO,
    *const BYTE,
    DWORD,
    *mut BYTE,
    *mut DWORD,
) -> BOOL;
pub type FnCryptVerifyTimeStampSignature = unsafe extern "system" fn(
    *const BYTE,
    DWORD,
    *const BYTE,
    DWORD,
    HCERTSTORE,
    *mut PCRYPT_TIMESTAMP_CONTEXT,
    *mut PCCERT_CONTEXT,
    *mut HCERTSTORE,
) -> BOOL;
pub type FnPFXExportCertStore =
    unsafe extern "system" fn(HCERTSTORE, *mut CRYPT_DATA_BLOB, LPCWSTR, DWORD) -> BOOL;
pub type FnPFXExportCertStoreEx = unsafe extern "system" fn(
    HCERTSTORE,
    *mut CRYPT_DATA_BLOB,
    LPCWSTR,
    *mut c_void,
    DWORD,
) -> BOOL;
pub type FnPFXImportCertStore =
    unsafe extern "system" fn(*mut CRYPT_DATA_BLOB, LPCWSTR, DWORD) -> HCERTSTORE;
pub type FnPFXIsPFXBlob = unsafe extern "system" fn(*mut CRYPT_DATA_BLOB) -> BOOL;
pub type FnPFXVerifyPassword =
    unsafe extern "system" fn(*mut CRYPT_DATA_BLOB, LPCWSTR, DWORD) -> BOOL;
