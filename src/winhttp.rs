use winapi::ctypes::c_int;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::guiddef::{REFCLSID, REFIID};
use winapi::shared::minwindef::{BOOL, DWORD, LPCVOID, LPDWORD, LPVOID, USHORT};
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR, PCWSTR, PVOID};
use winapi::um::minwinbase::SYSTEMTIME;
use winapi::um::winhttp::{
    HINTERNET, INTERNET_PORT, LPURL_COMPONENTS, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO, WINHTTP_PROXY_RESULT,
    WINHTTP_STATUS_CALLBACK, WINHTTP_WEB_SOCKET_BUFFER_TYPE,
};

pub type FnDllCanUnloadNow = unsafe extern "system" fn() -> HRESULT;
pub type FnDllGetClassObject = unsafe extern "system" fn(REFCLSID, REFIID, *mut LPVOID) -> HRESULT;
pub type FnWinHttpAddRequestHeaders =
    unsafe extern "system" fn(HINTERNET, LPCWSTR, DWORD, DWORD) -> BOOL;
pub type FnWinHttpCheckPlatform = unsafe extern "system" fn() -> BOOL;
pub type FnWinHttpCloseHandle = unsafe extern "system" fn(HINTERNET) -> BOOL;
pub type FnWinHttpConnect =
    unsafe extern "system" fn(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) -> HINTERNET;
pub type FnWinHttpCrackUrl =
    unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS) -> BOOL;
pub type FnWinHttpCreateProxyResolver =
    unsafe extern "system" fn(HINTERNET, *mut HINTERNET) -> DWORD;
pub type FnWinHttpCreateUrl =
    unsafe extern "system" fn(LPURL_COMPONENTS, DWORD, LPWSTR, LPDWORD) -> BOOL;
pub type FnWinHttpDetectAutoProxyConfigUrl = unsafe extern "system" fn(DWORD, *mut LPWSTR) -> BOOL;
pub type FnWinHttpFreeProxyResult = unsafe extern "system" fn(*mut WINHTTP_PROXY_RESULT) -> ();
pub type FnWinHttpGetDefaultProxyConfiguration =
    unsafe extern "system" fn(*mut WINHTTP_PROXY_INFO) -> BOOL;
pub type FnWinHttpGetIEProxyConfigForCurrentUser =
    unsafe extern "system" fn(*mut WINHTTP_CURRENT_USER_IE_PROXY_CONFIG) -> BOOL;
pub type FnWinHttpGetProxyForUrl = unsafe extern "system" fn(
    HINTERNET,
    LPCWSTR,
    *mut WINHTTP_AUTOPROXY_OPTIONS,
    *mut WINHTTP_PROXY_INFO,
) -> BOOL;
pub type FnWinHttpGetProxyForUrlEx = unsafe extern "system" fn(
    HINTERNET,
    PCWSTR,
    *mut WINHTTP_AUTOPROXY_OPTIONS,
    DWORD_PTR,
) -> DWORD;
pub type FnWinHttpGetProxyResult =
    unsafe extern "system" fn(HINTERNET, *mut WINHTTP_PROXY_RESULT) -> DWORD;
pub type FnWinHttpOpen =
    unsafe extern "system" fn(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET;
pub type FnWinHttpOpenRequest = unsafe extern "system" fn(
    HINTERNET,
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
    LPCWSTR,
    *mut LPCWSTR,
    DWORD,
) -> HINTERNET;
pub type FnWinHttpQueryAuthSchemes =
    unsafe extern "system" fn(HINTERNET, LPDWORD, LPDWORD, LPDWORD) -> BOOL;
pub type FnWinHttpQueryDataAvailable = unsafe extern "system" fn(HINTERNET, LPDWORD) -> BOOL;
pub type FnWinHttpQueryHeaders =
    unsafe extern "system" fn(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD) -> BOOL;
pub type FnWinHttpQueryOption =
    unsafe extern "system" fn(HINTERNET, DWORD, LPVOID, LPDWORD) -> BOOL;
pub type FnWinHttpReadData = unsafe extern "system" fn(HINTERNET, LPVOID, DWORD, LPDWORD) -> BOOL;
pub type FnWinHttpReceiveResponse = unsafe extern "system" fn(HINTERNET, LPVOID) -> BOOL;
pub type FnWinHttpResetAutoProxy = unsafe extern "system" fn(HINTERNET, DWORD) -> DWORD;
pub type FnWinHttpSendRequest =
    unsafe extern "system" fn(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) -> BOOL;
pub type FnWinHttpSetCredentials =
    unsafe extern "system" fn(HINTERNET, DWORD, DWORD, LPCWSTR, LPCWSTR, LPVOID) -> BOOL;
pub type FnWinHttpSetDefaultProxyConfiguration =
    unsafe extern "system" fn(*mut WINHTTP_PROXY_INFO) -> BOOL;
pub type FnWinHttpSetOption = unsafe extern "system" fn(HINTERNET, DWORD, LPVOID, DWORD) -> BOOL;
pub type FnWinHttpSetStatusCallback = unsafe extern "system" fn(
    HINTERNET,
    WINHTTP_STATUS_CALLBACK,
    DWORD,
    DWORD_PTR,
) -> WINHTTP_STATUS_CALLBACK;
pub type FnWinHttpSetTimeouts =
    unsafe extern "system" fn(HINTERNET, c_int, c_int, c_int, c_int) -> BOOL;
pub type FnWinHttpTimeFromSystemTime = unsafe extern "system" fn(*const SYSTEMTIME, LPWSTR) -> BOOL;
pub type FnWinHttpTimeToSystemTime = unsafe extern "system" fn(LPCWSTR, *mut SYSTEMTIME) -> BOOL;
pub type FnWinHttpWebSocketClose =
    unsafe extern "system" fn(HINTERNET, USHORT, PVOID, DWORD) -> DWORD;
pub type FnWinHttpWebSocketCompleteUpgrade =
    unsafe extern "system" fn(HINTERNET, DWORD_PTR) -> HINTERNET;
pub type FnWinHttpWebSocketQueryCloseStatus =
    unsafe extern "system" fn(HINTERNET, *mut USHORT, PVOID, DWORD, *mut DWORD) -> DWORD;
pub type FnWinHttpWebSocketReceive = unsafe extern "system" fn(
    HINTERNET,
    PVOID,
    DWORD,
    *mut DWORD,
    *mut WINHTTP_WEB_SOCKET_BUFFER_TYPE,
) -> DWORD;
pub type FnWinHttpWebSocketSend =
    unsafe extern "system" fn(HINTERNET, WINHTTP_WEB_SOCKET_BUFFER_TYPE, PVOID, DWORD) -> DWORD;
pub type FnWinHttpWebSocketShutdown =
    unsafe extern "system" fn(HINTERNET, USHORT, PVOID, DWORD) -> DWORD;
pub type FnWinHttpWriteData = unsafe extern "system" fn(HINTERNET, LPCVOID, DWORD, LPDWORD) -> BOOL;
