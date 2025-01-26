use winapi::ctypes::{c_int, c_long, c_uint};
use winapi::shared::basetsd::{
    INT_PTR, LONG_PTR, PDWORD_PTR, PUINT_PTR, UINT32, UINT_PTR, ULONG_PTR,
};
use winapi::shared::guiddef::LPCGUID;
use winapi::shared::minwindef::{
    ATOM, BOOL, BYTE, DWORD, HINSTANCE, HKL, HMODULE, HRGN, HWINSTA, INT, LPARAM, LPBYTE, LPDWORD,
    LPINT, LPVOID, LPWORD, LRESULT, PBYTE, PUINT, PULONG, UINT, ULONG, WORD, WPARAM,
};
use winapi::shared::ntdef::{
    CHAR, HANDLE, LONG, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PVOID, SHORT, VOID, WCHAR,
};
use winapi::shared::windef::{
    COLORREF, DPI_AWARENESS, DPI_AWARENESS_CONTEXT, DPI_HOSTING_BEHAVIOR, HACCEL, HBITMAP, HBRUSH,
    HCURSOR, HDC, HDESK, HHOOK, HICON, HMENU, HMONITOR, HWINEVENTHOOK, HWND, LPCRECT, LPPOINT,
    LPRECT, POINT, RECT, SIZE,
};
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::wingdi::{BLENDFUNCTION, DEVMODEA, DEVMODEW, PDISPLAY_DEVICEA, PDISPLAY_DEVICEW};
use winapi::um::winnt::{ACCESS_MASK, PSECURITY_DESCRIPTOR, PSECURITY_INFORMATION};
use winapi::um::winuser::{
    DESKTOPENUMPROCA, DESKTOPENUMPROCW, DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS,
    DIALOG_DPI_CHANGE_BEHAVIORS, DLGPROC, DRAWSTATEPROC, FEEDBACK_TYPE, GRAYSTRINGPROC, HDEVNOTIFY,
    HDWP, HOOKPROC, HPOWERNOTIFY, HRAWINPUT, HSYNTHETICPOINTERDEVICE, HTOUCHINPUT, INPUT_TRANSFORM,
    LPACCEL, LPCDLGTEMPLATEA, LPCDLGTEMPLATEW, LPCMENUINFO, LPCMENUITEMINFOA, LPCMENUITEMINFOW,
    LPDRAWTEXTPARAMS, LPINPUT, LPMENUINFO, LPMENUITEMINFOA, LPMENUITEMINFOW, LPMONITORINFO,
    LPMOUSEMOVEPOINT, LPMSG, LPPAINTSTRUCT, LPTPMPARAMS, LPTRACKMOUSEEVENT, LPWNDCLASSA,
    LPWNDCLASSEXA, LPWNDCLASSEXW, LPWNDCLASSW, MENUTEMPLATEA, MENUTEMPLATEW, MONITORENUMPROC, MSG,
    MSGBOXPARAMSA, MSGBOXPARAMSW, PAINTSTRUCT, PALTTABINFO, PBSMINFO, PCHANGEFILTERSTRUCT,
    PCOMBOBOXINFO, PCRAWINPUTDEVICE, PCURSORINFO, PFLASHWINFO, PGUITHREADINFO, PICONINFO,
    PLASTINPUTINFO, PMENUBARINFO, POINTER_FEEDBACK_MODE, POINTER_INFO, POINTER_INPUT_TYPE,
    POINTER_PEN_INFO, POINTER_TOUCH_INFO, POINTER_TYPE_INFO, PRAWINPUT, PRAWINPUTDEVICE,
    PRAWINPUTDEVICELIST, PROPENUMPROCA, PROPENUMPROCW, PSCROLLBARINFO, PTITLEBARINFO, PTOUCHINPUT,
    PWINDOWINFO, SCROLLINFO, SENDASYNCPROC, TIMERPROC, TOUCH_HIT_TESTING_INPUT,
    TOUCH_HIT_TESTING_PROXIMITY_EVALUATION, UPDATELAYEREDWINDOWINFO, WINDOWPLACEMENT, WINEVENTPROC,
    WINSTAENUMPROCA, WINSTAENUMPROCW, WNDCLASSA, WNDCLASSEXA, WNDCLASSEXW, WNDCLASSW, WNDENUMPROC,
    WNDPROC,
};
use winapi::vc::vadefs::va_list;

pub type FnActivateKeyboardLayout = unsafe extern "system" fn(HKL, UINT) -> HKL;
pub type FnAddClipboardFormatListener = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnAdjustWindowRect = unsafe extern "system" fn(LPRECT, DWORD, BOOL) -> BOOL;
pub type FnAdjustWindowRectEx = unsafe extern "system" fn(LPRECT, DWORD, BOOL, DWORD) -> BOOL;
pub type FnAdjustWindowRectExForDpi =
    unsafe extern "system" fn(LPRECT, DWORD, BOOL, DWORD, UINT) -> BOOL;
pub type FnAllowSetForegroundWindow = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnAnimateWindow = unsafe extern "system" fn(HWND, DWORD, DWORD) -> BOOL;
pub type FnAnyPopup = unsafe extern "system" fn() -> BOOL;
pub type FnAppendMenuA = unsafe extern "system" fn(HMENU, UINT, UINT_PTR, LPCSTR) -> BOOL;
pub type FnAppendMenuW = unsafe extern "system" fn(HMENU, UINT, UINT_PTR, LPCWSTR) -> BOOL;
pub type FnAreDpiAwarenessContextsEqual =
    unsafe extern "system" fn(DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT) -> BOOL;
pub type FnArrangeIconicWindows = unsafe extern "system" fn(HWND) -> UINT;
pub type FnAttachThreadInput = unsafe extern "system" fn(DWORD, DWORD, BOOL) -> BOOL;
pub type FnBeginDeferWindowPos = unsafe extern "system" fn(c_int) -> HDWP;
pub type FnBeginPaint = unsafe extern "system" fn(HWND, LPPAINTSTRUCT) -> HDC;
pub type FnBlockInput = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnBringWindowToTop = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnBroadcastSystemMessageA =
    unsafe extern "system" fn(DWORD, LPDWORD, UINT, WPARAM, LPARAM) -> LONG;
pub type FnBroadcastSystemMessageExA =
    unsafe extern "system" fn(DWORD, LPDWORD, UINT, WPARAM, LPARAM, PBSMINFO) -> c_long;
pub type FnBroadcastSystemMessageExW =
    unsafe extern "system" fn(DWORD, LPDWORD, UINT, WPARAM, LPARAM, PBSMINFO) -> c_long;
pub type FnBroadcastSystemMessageW =
    unsafe extern "system" fn(DWORD, LPDWORD, UINT, WPARAM, LPARAM) -> LONG;
pub type FnCalculatePopupWindowPosition =
    unsafe extern "system" fn(*const POINT, *const SIZE, UINT, *mut RECT, *mut RECT) -> BOOL;
pub type FnCallMsgFilterA = unsafe extern "system" fn(LPMSG, c_int) -> BOOL;
pub type FnCallMsgFilterW = unsafe extern "system" fn(LPMSG, c_int) -> BOOL;
pub type FnCallNextHookEx = unsafe extern "system" fn(HHOOK, c_int, WPARAM, LPARAM) -> LRESULT;
pub type FnCallWindowProcA =
    unsafe extern "system" fn(WNDPROC, HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnCallWindowProcW =
    unsafe extern "system" fn(WNDPROC, HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnCancelShutdown = unsafe extern "system" fn() -> BOOL;
pub type FnCascadeWindows =
    unsafe extern "system" fn(HWND, UINT, *const RECT, UINT, *const HWND) -> WORD;
pub type FnChangeClipboardChain = unsafe extern "system" fn(HWND, HWND) -> BOOL;
pub type FnChangeDisplaySettingsA = unsafe extern "system" fn(*mut DEVMODEA, DWORD) -> LONG;
pub type FnChangeDisplaySettingsExA =
    unsafe extern "system" fn(LPCSTR, *mut DEVMODEA, HWND, DWORD, LPVOID) -> LONG;
pub type FnChangeDisplaySettingsExW =
    unsafe extern "system" fn(LPCWSTR, *mut DEVMODEW, HWND, DWORD, LPVOID) -> LONG;
pub type FnChangeDisplaySettingsW = unsafe extern "system" fn(*mut DEVMODEW, DWORD) -> LONG;
pub type FnChangeMenuA = unsafe extern "system" fn(HMENU, UINT, LPCSTR, UINT, UINT) -> BOOL;
pub type FnChangeMenuW = unsafe extern "system" fn(HMENU, UINT, LPCWSTR, UINT, UINT) -> BOOL;
pub type FnChangeWindowMessageFilter = unsafe extern "system" fn(UINT, DWORD) -> BOOL;
pub type FnChangeWindowMessageFilterEx =
    unsafe extern "system" fn(HWND, UINT, DWORD, PCHANGEFILTERSTRUCT) -> BOOL;
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
pub type FnCharToOemA = unsafe extern "system" fn(LPCSTR, LPSTR) -> BOOL;
pub type FnCharToOemBuffA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> BOOL;
pub type FnCharToOemBuffW = unsafe extern "system" fn(LPCWSTR, LPSTR, DWORD) -> BOOL;
pub type FnCharToOemW = unsafe extern "system" fn(LPCWSTR, LPSTR) -> BOOL;
pub type FnCharUpperA = unsafe extern "system" fn(LPSTR) -> LPSTR;
pub type FnCharUpperBuffA = unsafe extern "system" fn(LPSTR, DWORD) -> DWORD;
pub type FnCharUpperBuffW = unsafe extern "system" fn(LPWSTR, DWORD) -> DWORD;
pub type FnCharUpperW = unsafe extern "system" fn(LPWSTR) -> LPWSTR;
pub type FnCheckDlgButton = unsafe extern "system" fn(HWND, c_int, UINT) -> BOOL;
pub type FnCheckMenuItem = unsafe extern "system" fn(HMENU, UINT, UINT) -> DWORD;
pub type FnCheckMenuRadioItem = unsafe extern "system" fn(HMENU, UINT, UINT, UINT, UINT) -> BOOL;
pub type FnCheckRadioButton = unsafe extern "system" fn(HWND, c_int, c_int, c_int) -> BOOL;
pub type FnChildWindowFromPoint = unsafe extern "system" fn(HWND, POINT) -> HWND;
pub type FnChildWindowFromPointEx = unsafe extern "system" fn(HWND, POINT, UINT) -> HWND;
pub type FnClientToScreen = unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnClipCursor = unsafe extern "system" fn(*const RECT) -> BOOL;
pub type FnCloseClipboard = unsafe extern "system" fn() -> BOOL;
pub type FnCloseDesktop = unsafe extern "system" fn(HDESK) -> BOOL;
pub type FnCloseTouchInputHandle = unsafe extern "system" fn(HTOUCHINPUT) -> BOOL;
pub type FnCloseWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnCloseWindowStation = unsafe extern "system" fn(HWINSTA) -> BOOL;
pub type FnCopyAcceleratorTableA = unsafe extern "system" fn(HACCEL, LPACCEL, c_int) -> c_int;
pub type FnCopyAcceleratorTableW = unsafe extern "system" fn(HACCEL, LPACCEL, c_int) -> c_int;
pub type FnCopyIcon = unsafe extern "system" fn(HICON) -> HICON;
pub type FnCopyImage = unsafe extern "system" fn(HANDLE, UINT, c_int, c_int, UINT) -> HANDLE;
pub type FnCopyRect = unsafe extern "system" fn(LPRECT, *const RECT) -> BOOL;
pub type FnCountClipboardFormats = unsafe extern "system" fn() -> c_int;
pub type FnCreateAcceleratorTableA = unsafe extern "system" fn(LPACCEL, c_int) -> HACCEL;
pub type FnCreateAcceleratorTableW = unsafe extern "system" fn(LPACCEL, c_int) -> HACCEL;
pub type FnCreateCaret = unsafe extern "system" fn(HWND, HBITMAP, c_int, c_int) -> BOOL;
pub type FnCreateCursor = unsafe extern "system" fn(
    HINSTANCE,
    c_int,
    c_int,
    c_int,
    c_int,
    *const VOID,
    *const VOID,
) -> HCURSOR;
pub type FnCreateDesktopA = unsafe extern "system" fn(
    LPCSTR,
    LPCSTR,
    *mut DEVMODEA,
    DWORD,
    ACCESS_MASK,
    LPSECURITY_ATTRIBUTES,
) -> HDESK;
pub type FnCreateDesktopExA = unsafe extern "system" fn(
    LPCSTR,
    LPCSTR,
    *mut DEVMODEA,
    DWORD,
    ACCESS_MASK,
    LPSECURITY_ATTRIBUTES,
    ULONG,
    PVOID,
) -> HDESK;
pub type FnCreateDesktopExW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    *mut DEVMODEW,
    DWORD,
    ACCESS_MASK,
    LPSECURITY_ATTRIBUTES,
    ULONG,
    PVOID,
) -> HDESK;
pub type FnCreateDesktopW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    *mut DEVMODEW,
    DWORD,
    ACCESS_MASK,
    LPSECURITY_ATTRIBUTES,
) -> HDESK;
pub type FnCreateDialogIndirectParamA =
    unsafe extern "system" fn(HINSTANCE, LPCDLGTEMPLATEA, HWND, DLGPROC, LPARAM) -> HWND;
pub type FnCreateDialogIndirectParamW =
    unsafe extern "system" fn(HINSTANCE, LPCDLGTEMPLATEW, HWND, DLGPROC, LPARAM) -> HWND;
pub type FnCreateDialogParamA =
    unsafe extern "system" fn(HINSTANCE, LPCSTR, HWND, DLGPROC, LPARAM) -> HWND;
pub type FnCreateDialogParamW =
    unsafe extern "system" fn(HINSTANCE, LPCWSTR, HWND, DLGPROC, LPARAM) -> HWND;
pub type FnCreateIcon = unsafe extern "system" fn(
    HINSTANCE,
    c_int,
    c_int,
    BYTE,
    BYTE,
    *const BYTE,
    *const BYTE,
) -> HICON;
pub type FnCreateIconFromResource = unsafe extern "system" fn(PBYTE, DWORD, BOOL, DWORD) -> HICON;
pub type FnCreateIconFromResourceEx =
    unsafe extern "system" fn(PBYTE, DWORD, BOOL, DWORD, c_int, c_int, UINT) -> HICON;
pub type FnCreateIconIndirect = unsafe extern "system" fn(PICONINFO) -> HICON;
pub type FnCreateMDIWindowA = unsafe extern "system" fn(
    LPCSTR,
    LPCSTR,
    DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    HWND,
    HINSTANCE,
    LPARAM,
) -> HWND;
pub type FnCreateMDIWindowW = unsafe extern "system" fn(
    LPCWSTR,
    LPCWSTR,
    DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    HWND,
    HINSTANCE,
    LPARAM,
) -> HWND;
pub type FnCreateMenu = unsafe extern "system" fn() -> HMENU;
pub type FnCreatePopupMenu = unsafe extern "system" fn() -> HMENU;
pub type FnCreateSyntheticPointerDevice = unsafe extern "system" fn(
    POINTER_INPUT_TYPE,
    ULONG,
    POINTER_FEEDBACK_MODE,
) -> HSYNTHETICPOINTERDEVICE;
pub type FnCreateWindowExA = unsafe extern "system" fn(
    DWORD,
    LPCSTR,
    LPCSTR,
    DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    HWND,
    HMENU,
    HINSTANCE,
    LPVOID,
) -> HWND;
pub type FnCreateWindowExW = unsafe extern "system" fn(
    DWORD,
    LPCWSTR,
    LPCWSTR,
    DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    HWND,
    HMENU,
    HINSTANCE,
    LPVOID,
) -> HWND;
pub type FnCreateWindowStationA =
    unsafe extern "system" fn(LPCSTR, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES) -> HWINSTA;
pub type FnCreateWindowStationW =
    unsafe extern "system" fn(LPCWSTR, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES) -> HWINSTA;
pub type FnDefDlgProcA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefDlgProcW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefFrameProcA = unsafe extern "system" fn(HWND, HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefFrameProcW = unsafe extern "system" fn(HWND, HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefMDIChildProcA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefMDIChildProcW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefRawInputProc = unsafe extern "system" fn(*mut PRAWINPUT, INT, UINT) -> LRESULT;
pub type FnDefWindowProcA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDefWindowProcW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnDeferWindowPos =
    unsafe extern "system" fn(HDWP, HWND, HWND, c_int, c_int, c_int, c_int, UINT) -> HDWP;
pub type FnDeleteMenu = unsafe extern "system" fn(HMENU, UINT, UINT) -> BOOL;
pub type FnDeregisterShellHookWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnDestroyAcceleratorTable = unsafe extern "system" fn(HACCEL) -> BOOL;
pub type FnDestroyCaret = unsafe extern "system" fn() -> BOOL;
pub type FnDestroyCursor = unsafe extern "system" fn(HCURSOR) -> BOOL;
pub type FnDestroyIcon = unsafe extern "system" fn(HICON) -> BOOL;
pub type FnDestroyMenu = unsafe extern "system" fn(HMENU) -> BOOL;
pub type FnDestroySyntheticPointerDevice = unsafe extern "system" fn(HSYNTHETICPOINTERDEVICE) -> ();
pub type FnDestroyWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnDialogBoxIndirectParamA =
    unsafe extern "system" fn(HINSTANCE, LPCDLGTEMPLATEA, HWND, DLGPROC, LPARAM) -> INT_PTR;
pub type FnDialogBoxIndirectParamW =
    unsafe extern "system" fn(HINSTANCE, LPCDLGTEMPLATEW, HWND, DLGPROC, LPARAM) -> INT_PTR;
pub type FnDialogBoxParamA =
    unsafe extern "system" fn(HINSTANCE, LPCSTR, HWND, DLGPROC, LPARAM) -> INT_PTR;
pub type FnDialogBoxParamW =
    unsafe extern "system" fn(HINSTANCE, LPCWSTR, HWND, DLGPROC, LPARAM) -> INT_PTR;
pub type FnDisableProcessWindowsGhosting = unsafe extern "system" fn() -> ();
pub type FnDispatchMessageA = unsafe extern "system" fn(*const MSG) -> LRESULT;
pub type FnDispatchMessageW = unsafe extern "system" fn(*const MSG) -> LRESULT;
pub type FnDlgDirListA = unsafe extern "system" fn(HWND, LPSTR, c_int, c_int, UINT) -> c_int;
pub type FnDlgDirListComboBoxA =
    unsafe extern "system" fn(HWND, LPSTR, c_int, c_int, UINT) -> c_int;
pub type FnDlgDirListComboBoxW =
    unsafe extern "system" fn(HWND, LPWSTR, c_int, c_int, UINT) -> c_int;
pub type FnDlgDirListW = unsafe extern "system" fn(HWND, LPWSTR, c_int, c_int, UINT) -> c_int;
pub type FnDlgDirSelectComboBoxExA = unsafe extern "system" fn(HWND, LPSTR, c_int, c_int) -> BOOL;
pub type FnDlgDirSelectComboBoxExW = unsafe extern "system" fn(HWND, LPWSTR, c_int, c_int) -> BOOL;
pub type FnDlgDirSelectExA = unsafe extern "system" fn(HWND, LPSTR, c_int, c_int) -> BOOL;
pub type FnDlgDirSelectExW = unsafe extern "system" fn(HWND, LPWSTR, c_int, c_int) -> BOOL;
pub type FnDragDetect = unsafe extern "system" fn(HWND, POINT) -> BOOL;
pub type FnDragObject = unsafe extern "system" fn(HWND, HWND, UINT, ULONG_PTR, HCURSOR) -> DWORD;
pub type FnDrawAnimatedRects =
    unsafe extern "system" fn(HWND, c_int, *const RECT, *const RECT) -> BOOL;
pub type FnDrawCaption = unsafe extern "system" fn(HWND, HDC, *const RECT, UINT) -> BOOL;
pub type FnDrawEdge = unsafe extern "system" fn(HDC, LPRECT, UINT, UINT) -> BOOL;
pub type FnDrawFocusRect = unsafe extern "system" fn(HDC, *const RECT) -> BOOL;
pub type FnDrawFrameControl = unsafe extern "system" fn(HDC, LPRECT, UINT, UINT) -> BOOL;
pub type FnDrawIcon = unsafe extern "system" fn(HDC, c_int, c_int, HICON) -> BOOL;
pub type FnDrawIconEx =
    unsafe extern "system" fn(HDC, c_int, c_int, HICON, c_int, c_int, UINT, HBRUSH, UINT) -> BOOL;
pub type FnDrawMenuBar = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnDrawStateA = unsafe extern "system" fn(
    HDC,
    HBRUSH,
    DRAWSTATEPROC,
    LPARAM,
    WPARAM,
    c_int,
    c_int,
    c_int,
    c_int,
    UINT,
) -> BOOL;
pub type FnDrawStateW = unsafe extern "system" fn(
    HDC,
    HBRUSH,
    DRAWSTATEPROC,
    LPARAM,
    WPARAM,
    c_int,
    c_int,
    c_int,
    c_int,
    UINT,
) -> BOOL;
pub type FnDrawTextA = unsafe extern "system" fn(HDC, LPCSTR, c_int, LPRECT, UINT) -> c_int;
pub type FnDrawTextExA =
    unsafe extern "system" fn(HDC, LPCSTR, c_int, LPRECT, UINT, LPDRAWTEXTPARAMS) -> c_int;
pub type FnDrawTextExW =
    unsafe extern "system" fn(HDC, LPCWSTR, c_int, LPRECT, UINT, LPDRAWTEXTPARAMS) -> c_int;
pub type FnDrawTextW = unsafe extern "system" fn(HDC, LPCWSTR, c_int, LPRECT, UINT) -> c_int;
pub type FnEmptyClipboard = unsafe extern "system" fn() -> BOOL;
pub type FnEnableMenuItem = unsafe extern "system" fn(HMENU, UINT, UINT) -> BOOL;
pub type FnEnableMouseInPointer = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnEnableNonClientDpiScaling = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnEnableScrollBar = unsafe extern "system" fn(HWND, UINT, UINT) -> BOOL;
pub type FnEnableWindow = unsafe extern "system" fn(HWND, BOOL) -> BOOL;
pub type FnEndDeferWindowPos = unsafe extern "system" fn(HDWP) -> BOOL;
pub type FnEndDialog = unsafe extern "system" fn(HWND, INT_PTR) -> BOOL;
pub type FnEndMenu = unsafe extern "system" fn(HMENU, UINT, UINT_PTR, LPCSTR) -> BOOL;
pub type FnEndPaint = unsafe extern "system" fn(HWND, *const PAINTSTRUCT) -> BOOL;
pub type FnEndTask = unsafe extern "system" fn(HWND, BOOL, BOOL) -> BOOL;
pub type FnEnumChildWindows = unsafe extern "system" fn(HWND, WNDENUMPROC, LPARAM) -> BOOL;
pub type FnEnumClipboardFormats = unsafe extern "system" fn(UINT) -> UINT;
pub type FnEnumDesktopWindows = unsafe extern "system" fn(HDESK, WNDENUMPROC, LPARAM) -> BOOL;
pub type FnEnumDesktopsA = unsafe extern "system" fn(HWINSTA, DESKTOPENUMPROCA, LPARAM) -> BOOL;
pub type FnEnumDesktopsW = unsafe extern "system" fn(HWINSTA, DESKTOPENUMPROCW, LPARAM) -> BOOL;
pub type FnEnumDisplayDevicesA =
    unsafe extern "system" fn(LPCSTR, DWORD, PDISPLAY_DEVICEA, DWORD) -> BOOL;
pub type FnEnumDisplayDevicesW =
    unsafe extern "system" fn(LPCWSTR, DWORD, PDISPLAY_DEVICEW, DWORD) -> BOOL;
pub type FnEnumDisplayMonitors =
    unsafe extern "system" fn(HDC, LPCRECT, MONITORENUMPROC, LPARAM) -> BOOL;
pub type FnEnumDisplaySettingsA = unsafe extern "system" fn(LPCSTR, DWORD, *mut DEVMODEA) -> BOOL;
pub type FnEnumDisplaySettingsExA =
    unsafe extern "system" fn(LPCSTR, DWORD, *mut DEVMODEA, DWORD) -> BOOL;
pub type FnEnumDisplaySettingsExW =
    unsafe extern "system" fn(LPCWSTR, DWORD, *mut DEVMODEW, DWORD) -> BOOL;
pub type FnEnumDisplaySettingsW = unsafe extern "system" fn(LPCWSTR, DWORD, *mut DEVMODEW) -> BOOL;
pub type FnEnumPropsA = unsafe extern "system" fn(HWND, PROPENUMPROCA) -> c_int;
pub type FnEnumPropsExA = unsafe extern "system" fn(HWND, PROPENUMPROCA, LPARAM) -> c_int;
pub type FnEnumPropsExW = unsafe extern "system" fn(HWND, PROPENUMPROCW, LPARAM) -> c_int;
pub type FnEnumPropsW = unsafe extern "system" fn(HWND, PROPENUMPROCW) -> c_int;
pub type FnEnumThreadWindows = unsafe extern "system" fn(DWORD, WNDENUMPROC, LPARAM) -> BOOL;
pub type FnEnumWindowStationsA = unsafe extern "system" fn(WINSTAENUMPROCA, LPARAM) -> BOOL;
pub type FnEnumWindowStationsW = unsafe extern "system" fn(WINSTAENUMPROCW, LPARAM) -> BOOL;
pub type FnEnumWindows = unsafe extern "system" fn(WNDENUMPROC, LPARAM) -> BOOL;
pub type FnEqualRect = unsafe extern "system" fn(*const RECT, *const RECT) -> BOOL;
pub type FnEvaluateProximityToPolygon = unsafe extern "system" fn(
    UINT32,
    *const POINT,
    *const TOUCH_HIT_TESTING_INPUT,
    *mut TOUCH_HIT_TESTING_PROXIMITY_EVALUATION,
) -> BOOL;
pub type FnEvaluateProximityToRect = unsafe extern "system" fn(
    *const RECT,
    *const TOUCH_HIT_TESTING_INPUT,
    *mut TOUCH_HIT_TESTING_PROXIMITY_EVALUATION,
) -> BOOL;
pub type FnExcludeUpdateRgn = unsafe extern "system" fn(HDC, HWND) -> c_int;
pub type FnExitWindowsEx = unsafe extern "system" fn(UINT, DWORD) -> BOOL;
pub type FnFillRect = unsafe extern "system" fn(HDC, *const RECT, HBRUSH) -> c_int;
pub type FnFindWindowA = unsafe extern "system" fn(LPCSTR, LPCSTR) -> HWND;
pub type FnFindWindowExA = unsafe extern "system" fn(HWND, HWND, LPCSTR, LPCSTR) -> HWND;
pub type FnFindWindowExW = unsafe extern "system" fn(HWND, HWND, LPCWSTR, LPCWSTR) -> HWND;
pub type FnFindWindowW = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> HWND;
pub type FnFlashWindow = unsafe extern "system" fn(HWND, BOOL) -> BOOL;
pub type FnFlashWindowEx = unsafe extern "system" fn(PFLASHWINFO) -> BOOL;
pub type FnFrameRect = unsafe extern "system" fn(HDC, *const RECT, HBRUSH) -> c_int;
pub type FnGetActiveWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetAltTabInfoA =
    unsafe extern "system" fn(HWND, c_int, PALTTABINFO, LPSTR, UINT) -> BOOL;
pub type FnGetAltTabInfoW =
    unsafe extern "system" fn(HWND, c_int, PALTTABINFO, LPWSTR, UINT) -> BOOL;
pub type FnGetAncestor = unsafe extern "system" fn(HWND, UINT) -> HWND;
pub type FnGetAsyncKeyState = unsafe extern "system" fn(c_int) -> SHORT;
pub type FnGetAwarenessFromDpiAwarenessContext =
    unsafe extern "system" fn(DPI_AWARENESS_CONTEXT) -> DPI_AWARENESS;
pub type FnGetCapture = unsafe extern "system" fn() -> HWND;
pub type FnGetCaretBlinkTime = unsafe extern "system" fn() -> UINT;
pub type FnGetCaretPos = unsafe extern "system" fn(LPPOINT) -> BOOL;
pub type FnGetClassInfoA = unsafe extern "system" fn(HINSTANCE, LPCSTR, LPWNDCLASSA) -> BOOL;
pub type FnGetClassInfoExA = unsafe extern "system" fn(HINSTANCE, LPCSTR, LPWNDCLASSEXA) -> BOOL;
pub type FnGetClassInfoExW = unsafe extern "system" fn(HINSTANCE, LPCWSTR, LPWNDCLASSEXW) -> BOOL;
pub type FnGetClassInfoW = unsafe extern "system" fn(HINSTANCE, LPCWSTR, LPWNDCLASSW) -> BOOL;
pub type FnGetClassLongA = unsafe extern "system" fn(HWND, c_int) -> DWORD;
pub type FnGetClassLongPtrA = unsafe extern "system" fn(HWND, c_int) -> ULONG_PTR;
pub type FnGetClassLongPtrW = unsafe extern "system" fn(HWND, c_int) -> ULONG_PTR;
pub type FnGetClassLongW = unsafe extern "system" fn(HWND, c_int) -> DWORD;
pub type FnGetClassNameA = unsafe extern "system" fn(HWND, LPCSTR, c_int) -> c_int;
pub type FnGetClassNameW = unsafe extern "system" fn(HWND, LPCWSTR, c_int) -> c_int;
pub type FnGetClassWord = unsafe extern "system" fn(HWND, c_int) -> WORD;
pub type FnGetClientRect = unsafe extern "system" fn(HWND, LPRECT) -> BOOL;
pub type FnGetClipCursor = unsafe extern "system" fn(LPRECT) -> BOOL;
pub type FnGetClipboardData = unsafe extern "system" fn(UINT) -> HANDLE;
pub type FnGetClipboardFormatNameA = unsafe extern "system" fn(UINT, LPSTR, c_int) -> c_int;
pub type FnGetClipboardFormatNameW = unsafe extern "system" fn(UINT, LPWSTR, c_int) -> c_int;
pub type FnGetClipboardOwner = unsafe extern "system" fn() -> HWND;
pub type FnGetClipboardSequenceNumber = unsafe extern "system" fn() -> DWORD;
pub type FnGetClipboardViewer = unsafe extern "system" fn() -> HWND;
pub type FnGetComboBoxInfo = unsafe extern "system" fn(HWND, PCOMBOBOXINFO) -> BOOL;
pub type FnGetCursor = unsafe extern "system" fn() -> HCURSOR;
pub type FnGetCursorInfo = unsafe extern "system" fn(PCURSORINFO) -> BOOL;
pub type FnGetCursorPos = unsafe extern "system" fn(LPPOINT) -> BOOL;
pub type FnGetDC = unsafe extern "system" fn(HWND) -> HDC;
pub type FnGetDCEx = unsafe extern "system" fn(HWND, HRGN, DWORD) -> HDC;
pub type FnGetDesktopWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetDialogBaseUnits = unsafe extern "system" fn() -> LONG;
pub type FnGetDialogControlDpiChangeBehavior =
    unsafe extern "system" fn(HWND) -> DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS;
pub type FnGetDialogDpiChangeBehavior =
    unsafe extern "system" fn(HWND) -> DIALOG_DPI_CHANGE_BEHAVIORS;
pub type FnGetDlgCtrlID = unsafe extern "system" fn(HWND) -> c_int;
pub type FnGetDlgItem = unsafe extern "system" fn(HWND, c_int) -> HWND;
pub type FnGetDlgItemInt = unsafe extern "system" fn(HWND, c_int, *mut BOOL, BOOL) -> UINT;
pub type FnGetDlgItemTextA = unsafe extern "system" fn(HWND, c_int, LPSTR, c_int) -> UINT;
pub type FnGetDlgItemTextW = unsafe extern "system" fn(HWND, c_int, LPWSTR, c_int) -> UINT;
pub type FnGetDoubleClickTime = unsafe extern "system" fn() -> UINT;
pub type FnGetDpiForSystem = unsafe extern "system" fn() -> UINT;
pub type FnGetDpiForWindow = unsafe extern "system" fn(HWND) -> UINT;
pub type FnGetDpiFromDpiAwarenessContext = unsafe extern "system" fn(DPI_AWARENESS_CONTEXT) -> UINT;
pub type FnGetFocus = unsafe extern "system" fn() -> HWND;
pub type FnGetForegroundWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetGUIThreadInfo = unsafe extern "system" fn(DWORD, PGUITHREADINFO) -> BOOL;
pub type FnGetIconInfo = unsafe extern "system" fn(HICON, PICONINFO) -> BOOL;
pub type FnGetInputState = unsafe extern "system" fn() -> BOOL;
pub type FnGetKBCodePage = unsafe extern "system" fn() -> UINT;
pub type FnGetKeyNameTextA = unsafe extern "system" fn(LONG, LPSTR, c_int) -> c_int;
pub type FnGetKeyNameTextW = unsafe extern "system" fn(LONG, LPWSTR, c_int) -> c_int;
pub type FnGetKeyState = unsafe extern "system" fn(c_int) -> SHORT;
pub type FnGetKeyboardLayout = unsafe extern "system" fn(DWORD) -> HKL;
pub type FnGetKeyboardLayoutList = unsafe extern "system" fn(c_int, *mut HKL) -> c_int;
pub type FnGetKeyboardLayoutNameA = unsafe extern "system" fn(LPSTR) -> BOOL;
pub type FnGetKeyboardLayoutNameW = unsafe extern "system" fn(LPWSTR) -> BOOL;
pub type FnGetKeyboardState = unsafe extern "system" fn(PBYTE) -> BOOL;
pub type FnGetKeyboardType = unsafe extern "system" fn(c_int) -> c_int;
pub type FnGetLastActivePopup = unsafe extern "system" fn(HWND) -> HWND;
pub type FnGetLastInputInfo = unsafe extern "system" fn(PLASTINPUTINFO) -> BOOL;
pub type FnGetLayeredWindowAttributes =
    unsafe extern "system" fn(HWND, *mut COLORREF, *mut BYTE, *mut DWORD) -> BOOL;
pub type FnGetListBoxInfo = unsafe extern "system" fn(HWND) -> DWORD;
pub type FnGetMenu = unsafe extern "system" fn(HWND) -> HMENU;
pub type FnGetMenuBarInfo = unsafe extern "system" fn(HWND, LONG, LONG, PMENUBARINFO) -> BOOL;
pub type FnGetMenuCheckMarkDimensions = unsafe extern "system" fn() -> LONG;
pub type FnGetMenuContextHelpId = unsafe extern "system" fn(HMENU) -> DWORD;
pub type FnGetMenuDefaultItem = unsafe extern "system" fn(HMENU, UINT, UINT) -> UINT;
pub type FnGetMenuInfo = unsafe extern "system" fn(HMENU, LPMENUINFO) -> BOOL;
pub type FnGetMenuItemCount = unsafe extern "system" fn(HMENU) -> c_int;
pub type FnGetMenuItemID = unsafe extern "system" fn(HMENU, c_int) -> UINT;
pub type FnGetMenuItemInfoA = unsafe extern "system" fn(HMENU, UINT, BOOL, LPMENUITEMINFOA) -> BOOL;
pub type FnGetMenuItemInfoW = unsafe extern "system" fn(HMENU, UINT, BOOL, LPMENUITEMINFOW) -> BOOL;
pub type FnGetMenuItemRect = unsafe extern "system" fn(HWND, HMENU, UINT, LPRECT) -> BOOL;
pub type FnGetMenuState = unsafe extern "system" fn(HMENU, UINT, UINT) -> UINT;
pub type FnGetMenuStringA = unsafe extern "system" fn(HMENU, UINT, LPSTR, c_int, UINT) -> c_int;
pub type FnGetMenuStringW = unsafe extern "system" fn(HMENU, UINT, LPWSTR, c_int, UINT) -> c_int;
pub type FnGetMessageA = unsafe extern "system" fn(LPMSG, HWND, UINT, UINT) -> BOOL;
pub type FnGetMessageExtraInfo = unsafe extern "system" fn() -> LPARAM;
pub type FnGetMessagePos = unsafe extern "system" fn() -> DWORD;
pub type FnGetMessageTime = unsafe extern "system" fn() -> LONG;
pub type FnGetMessageW = unsafe extern "system" fn(LPMSG, HWND, UINT, UINT) -> BOOL;
pub type FnGetMonitorInfoA = unsafe extern "system" fn(HMONITOR, LPMONITORINFO) -> BOOL;
pub type FnGetMonitorInfoW = unsafe extern "system" fn(HMONITOR, LPMONITORINFO) -> BOOL;
pub type FnGetMouseMovePointsEx =
    unsafe extern "system" fn(UINT, LPMOUSEMOVEPOINT, LPMOUSEMOVEPOINT, c_int, DWORD) -> c_int;
pub type FnGetNextDlgGroupItem = unsafe extern "system" fn(HWND, HWND, BOOL) -> HWND;
pub type FnGetNextDlgTabItem = unsafe extern "system" fn(HWND, HWND, BOOL) -> HWND;
pub type FnGetOpenClipboardWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetParent = unsafe extern "system" fn(HWND) -> HWND;
pub type FnGetPhysicalCursorPos = unsafe extern "system" fn(LPPOINT) -> BOOL;
pub type FnGetPointerCursorId = unsafe extern "system" fn(UINT32, *mut UINT32) -> BOOL;
pub type FnGetPointerFrameInfo =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_INFO) -> BOOL;
pub type FnGetPointerFrameInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut UINT32, *mut POINTER_INFO) -> BOOL;
pub type FnGetPointerFramePenInfo =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_PEN_INFO) -> BOOL;
pub type FnGetPointerFramePenInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut UINT32, *mut POINTER_PEN_INFO) -> BOOL;
pub type FnGetPointerFrameTouchInfo =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_TOUCH_INFO) -> BOOL;
pub type FnGetPointerFrameTouchInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut UINT32, *mut POINTER_TOUCH_INFO) -> BOOL;
pub type FnGetPointerInfo = unsafe extern "system" fn(UINT32, *mut POINTER_INFO) -> BOOL;
pub type FnGetPointerInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_INFO) -> BOOL;
pub type FnGetPointerInputTransform =
    unsafe extern "system" fn(UINT32, UINT32, *mut INPUT_TRANSFORM) -> BOOL;
pub type FnGetPointerPenInfo = unsafe extern "system" fn(UINT32, *mut POINTER_PEN_INFO) -> BOOL;
pub type FnGetPointerPenInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_PEN_INFO) -> BOOL;
pub type FnGetPointerTouchInfo = unsafe extern "system" fn(UINT32, *mut POINTER_TOUCH_INFO) -> BOOL;
pub type FnGetPointerTouchInfoHistory =
    unsafe extern "system" fn(UINT32, *mut UINT32, *mut POINTER_TOUCH_INFO) -> BOOL;
pub type FnGetPointerType = unsafe extern "system" fn(UINT32, *mut POINTER_INPUT_TYPE) -> BOOL;
pub type FnGetPriorityClipboardFormat = unsafe extern "system" fn(*mut UINT, c_int) -> c_int;
pub type FnGetProcessDefaultLayout = unsafe extern "system" fn(*mut DWORD) -> BOOL;
pub type FnGetProcessWindowStation = unsafe extern "system" fn() -> HWINSTA;
pub type FnGetPropA = unsafe extern "system" fn(HWND, LPCSTR) -> HANDLE;
pub type FnGetPropW = unsafe extern "system" fn(HWND, LPCWSTR) -> HANDLE;
pub type FnGetQueueStatus = unsafe extern "system" fn(UINT) -> DWORD;
pub type FnGetRawInputBuffer = unsafe extern "system" fn(PRAWINPUT, PUINT, UINT) -> UINT;
pub type FnGetRawInputData =
    unsafe extern "system" fn(HRAWINPUT, UINT, LPVOID, PUINT, UINT) -> UINT;
pub type FnGetRawInputDeviceInfoA = unsafe extern "system" fn(HANDLE, UINT, LPVOID, PUINT) -> UINT;
pub type FnGetRawInputDeviceInfoW = unsafe extern "system" fn(HANDLE, UINT, LPVOID, PUINT) -> UINT;
pub type FnGetRawInputDeviceList =
    unsafe extern "system" fn(PRAWINPUTDEVICELIST, PUINT, UINT) -> UINT;
pub type FnGetRegisteredRawInputDevices =
    unsafe extern "system" fn(PRAWINPUTDEVICE, PUINT, UINT) -> UINT;
pub type FnGetScrollBarInfo = unsafe extern "system" fn(HWND, LONG, PSCROLLBARINFO) -> BOOL;
pub type FnGetScrollInfo = unsafe extern "system" fn(HWND, c_int, *mut SCROLLINFO) -> BOOL;
pub type FnGetScrollPos = unsafe extern "system" fn(HWND, c_int) -> c_int;
pub type FnGetScrollRange = unsafe extern "system" fn(HWND, c_int, LPINT, LPINT) -> BOOL;
pub type FnGetShellWindow = unsafe extern "system" fn() -> HWND;
pub type FnGetSubMenu = unsafe extern "system" fn(HMENU, c_int) -> HMENU;
pub type FnGetSysColor = unsafe extern "system" fn(c_int) -> DWORD;
pub type FnGetSysColorBrush = unsafe extern "system" fn(c_int) -> HBRUSH;
pub type FnGetSystemDpiForProcess = unsafe extern "system" fn(HANDLE) -> UINT;
pub type FnGetSystemMenu = unsafe extern "system" fn(HWND, BOOL) -> HMENU;
pub type FnGetSystemMetrics = unsafe extern "system" fn(c_int) -> c_int;
pub type FnGetSystemMetricsForDpi = unsafe extern "system" fn(c_int, UINT) -> c_int;
pub type FnGetTabbedTextExtentA =
    unsafe extern "system" fn(HDC, LPCSTR, c_int, c_int, *const INT) -> DWORD;
pub type FnGetTabbedTextExtentW =
    unsafe extern "system" fn(HDC, LPCWSTR, c_int, c_int, *const INT) -> DWORD;
pub type FnGetThreadDesktop = unsafe extern "system" fn(DWORD) -> HDESK;
pub type FnGetThreadDpiAwarenessContext = unsafe extern "system" fn() -> DPI_AWARENESS_CONTEXT;
pub type FnGetThreadDpiHostingBehavior = unsafe extern "system" fn() -> DPI_HOSTING_BEHAVIOR;
pub type FnGetTitleBarInfo = unsafe extern "system" fn(HWND, PTITLEBARINFO) -> BOOL;
pub type FnGetTopWindow = unsafe extern "system" fn(HWND) -> HWND;
pub type FnGetTouchInputInfo =
    unsafe extern "system" fn(HTOUCHINPUT, c_uint, PTOUCHINPUT, c_int) -> BOOL;
pub type FnGetUnpredictedMessagePos = unsafe extern "system" fn() -> DWORD;
pub type FnGetUpdateRect = unsafe extern "system" fn(HWND, LPRECT, BOOL) -> BOOL;
pub type FnGetUpdateRgn = unsafe extern "system" fn(HWND, HRGN, BOOL) -> c_int;
pub type FnGetUpdatedClipboardFormats = unsafe extern "system" fn(PUINT, UINT, PUINT) -> BOOL;
pub type FnGetUserObjectInformationA =
    unsafe extern "system" fn(HANDLE, c_int, PVOID, DWORD, LPDWORD) -> BOOL;
pub type FnGetUserObjectInformationW =
    unsafe extern "system" fn(HANDLE, c_int, PVOID, DWORD, LPDWORD) -> BOOL;
pub type FnGetUserObjectSecurity = unsafe extern "system" fn(
    HANDLE,
    PSECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
    DWORD,
    LPDWORD,
) -> BOOL;
pub type FnGetWindow = unsafe extern "system" fn(HWND, UINT) -> HWND;
pub type FnGetWindowContextHelpId = unsafe extern "system" fn(HWND) -> DWORD;
pub type FnGetWindowDC = unsafe extern "system" fn(HWND) -> HDC;
pub type FnGetWindowDisplayAffinity = unsafe extern "system" fn(HWND, *mut DWORD) -> BOOL;
pub type FnGetWindowDpiAwarenessContext = unsafe extern "system" fn(HWND) -> DPI_AWARENESS_CONTEXT;
pub type FnGetWindowDpiHostingBehavior = unsafe extern "system" fn(HWND) -> DPI_HOSTING_BEHAVIOR;
pub type FnGetWindowFeedbackSetting =
    unsafe extern "system" fn(HWND, FEEDBACK_TYPE, DWORD, *mut UINT32, *mut VOID) -> BOOL;
pub type FnGetWindowInfo = unsafe extern "system" fn(HWND, PWINDOWINFO) -> BOOL;
pub type FnGetWindowLongA = unsafe extern "system" fn(HWND, c_int) -> LONG;
pub type FnGetWindowLongPtrA = unsafe extern "system" fn(HWND, c_int) -> LONG_PTR;
pub type FnGetWindowLongPtrW = unsafe extern "system" fn(HWND, c_int) -> LONG_PTR;
pub type FnGetWindowLongW = unsafe extern "system" fn(HWND, c_int) -> LONG;
pub type FnGetWindowModuleFileNameA = unsafe extern "system" fn(HWND, LPCSTR, UINT) -> UINT;
pub type FnGetWindowModuleFileNameW = unsafe extern "system" fn(HWND, LPWSTR, UINT) -> UINT;
pub type FnGetWindowPlacement = unsafe extern "system" fn(HWND, *mut WINDOWPLACEMENT) -> BOOL;
pub type FnGetWindowRect = unsafe extern "system" fn(HWND, LPRECT) -> BOOL;
pub type FnGetWindowRgn = unsafe extern "system" fn(HWND, HRGN) -> c_int;
pub type FnGetWindowRgnBox = unsafe extern "system" fn(HWND, LPRECT) -> c_int;
pub type FnGetWindowTextA = unsafe extern "system" fn(HWND, LPSTR, c_int) -> c_int;
pub type FnGetWindowTextLengthA = unsafe extern "system" fn(HWND) -> c_int;
pub type FnGetWindowTextLengthW = unsafe extern "system" fn(HWND) -> c_int;
pub type FnGetWindowTextW = unsafe extern "system" fn(HWND, LPWSTR, c_int) -> c_int;
pub type FnGetWindowThreadProcessId = unsafe extern "system" fn(HWND, LPDWORD) -> DWORD;
pub type FnGetWindowWord = unsafe extern "system" fn(HWND, c_int) -> WORD;
pub type FnGrayStringA = unsafe extern "system" fn(
    HDC,
    HBRUSH,
    GRAYSTRINGPROC,
    LPARAM,
    c_int,
    c_int,
    c_int,
    c_int,
    c_int,
) -> BOOL;
pub type FnGrayStringW = unsafe extern "system" fn(
    HDC,
    HBRUSH,
    GRAYSTRINGPROC,
    LPARAM,
    c_int,
    c_int,
    c_int,
    c_int,
    c_int,
) -> BOOL;
pub type FnHideCaret = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnHiliteMenuItem = unsafe extern "system" fn(HWND, HMENU, UINT, UINT) -> BOOL;
pub type FnInSendMessage = unsafe extern "system" fn() -> BOOL;
pub type FnInSendMessageEx = unsafe extern "system" fn(LPVOID) -> DWORD;
pub type FnInflateRect = unsafe extern "system" fn(LPRECT, c_int, c_int) -> BOOL;
pub type FnInitializeTouchInjection = unsafe extern "system" fn(UINT32, DWORD) -> BOOL;
pub type FnInjectSyntheticPointerInput =
    unsafe extern "system" fn(HSYNTHETICPOINTERDEVICE, *const POINTER_TYPE_INFO, UINT32) -> BOOL;
pub type FnInjectTouchInput = unsafe extern "system" fn(UINT32, *const POINTER_TOUCH_INFO) -> BOOL;
pub type FnInsertMenuA = unsafe extern "system" fn(HMENU, UINT, UINT, UINT_PTR, LPCSTR) -> BOOL;
pub type FnInsertMenuItemA = unsafe extern "system" fn(HMENU, UINT, BOOL, LPCMENUITEMINFOA) -> BOOL;
pub type FnInsertMenuItemW = unsafe extern "system" fn(HMENU, UINT, BOOL, LPCMENUITEMINFOW) -> BOOL;
pub type FnInsertMenuW = unsafe extern "system" fn(HMENU, UINT, UINT, UINT_PTR, LPCWSTR) -> BOOL;
pub type FnInternalGetWindowText = unsafe extern "system" fn(HWND, LPWSTR, c_int) -> c_int;
pub type FnIntersectRect = unsafe extern "system" fn(LPRECT, *const RECT, *const RECT) -> BOOL;
pub type FnInvalidateRect = unsafe extern "system" fn(HWND, *const RECT, BOOL) -> BOOL;
pub type FnInvalidateRgn = unsafe extern "system" fn(HWND, HRGN, BOOL) -> BOOL;
pub type FnInvertRect = unsafe extern "system" fn(HDC, *const RECT) -> BOOL;
pub type FnIsCharAlphaA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharAlphaNumericA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharAlphaNumericW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharAlphaW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharLowerA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharLowerW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsCharUpperA = unsafe extern "system" fn(CHAR) -> BOOL;
pub type FnIsCharUpperW = unsafe extern "system" fn(WCHAR) -> BOOL;
pub type FnIsChild = unsafe extern "system" fn(HWND, HWND) -> BOOL;
pub type FnIsClipboardFormatAvailable = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnIsDialogMessageA = unsafe extern "system" fn(HWND, LPMSG) -> BOOL;
pub type FnIsDialogMessageW = unsafe extern "system" fn(HWND, LPMSG) -> BOOL;
pub type FnIsDlgButtonChecked = unsafe extern "system" fn(HWND, c_int) -> UINT;
pub type FnIsGUIThread = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnIsHungAppWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsIconic = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsImmersiveProcess = unsafe extern "system" fn(HANDLE) -> BOOL;
pub type FnIsMenu = unsafe extern "system" fn(HMENU) -> BOOL;
pub type FnIsMouseInPointerEnabled = unsafe extern "system" fn() -> BOOL;
pub type FnIsProcessDPIAware = unsafe extern "system" fn() -> BOOL;
pub type FnIsRectEmpty = unsafe extern "system" fn(*const RECT) -> BOOL;
pub type FnIsTouchWindow = unsafe extern "system" fn(HWND, PULONG) -> BOOL;
pub type FnIsValidDpiAwarenessContext = unsafe extern "system" fn(DPI_AWARENESS_CONTEXT) -> BOOL;
pub type FnIsWinEventHookInstalled = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnIsWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsWindowEnabled = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsWindowUnicode = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsWindowVisible = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnIsWow64Message = unsafe extern "system" fn() -> BOOL;
pub type FnIsZoomed = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnKillTimer = unsafe extern "system" fn(HWND, UINT_PTR) -> BOOL;
pub type FnLoadAcceleratorsA = unsafe extern "system" fn(HINSTANCE, LPCSTR) -> HACCEL;
pub type FnLoadAcceleratorsW = unsafe extern "system" fn(HINSTANCE, LPCWSTR) -> HACCEL;
pub type FnLoadBitmapA = unsafe extern "system" fn(HINSTANCE, LPCSTR) -> HBITMAP;
pub type FnLoadBitmapW = unsafe extern "system" fn(HINSTANCE, LPCWSTR) -> HBITMAP;
pub type FnLoadCursorA = unsafe extern "system" fn(HINSTANCE, LPCSTR) -> HCURSOR;
pub type FnLoadCursorFromFileA = unsafe extern "system" fn(LPCSTR) -> HCURSOR;
pub type FnLoadCursorFromFileW = unsafe extern "system" fn(LPCWSTR) -> HCURSOR;
pub type FnLoadCursorW = unsafe extern "system" fn(HINSTANCE, LPCWSTR) -> HCURSOR;
pub type FnLoadIconA = unsafe extern "system" fn(HINSTANCE, LPCSTR) -> HICON;
pub type FnLoadIconW = unsafe extern "system" fn(HINSTANCE, LPCWSTR) -> HICON;
pub type FnLoadImageA =
    unsafe extern "system" fn(HINSTANCE, LPCSTR, UINT, c_int, c_int, UINT) -> HANDLE;
pub type FnLoadImageW =
    unsafe extern "system" fn(HINSTANCE, LPCWSTR, UINT, c_int, c_int, UINT) -> HANDLE;
pub type FnLoadKeyboardLayoutA = unsafe extern "system" fn(LPCSTR, DWORD) -> HKL;
pub type FnLoadKeyboardLayoutW = unsafe extern "system" fn(LPCWSTR, DWORD) -> HKL;
pub type FnLoadMenuA = unsafe extern "system" fn(HINSTANCE, LPCSTR) -> HMENU;
pub type FnLoadMenuIndirectA = unsafe extern "system" fn(*const MENUTEMPLATEA) -> HMENU;
pub type FnLoadMenuIndirectW = unsafe extern "system" fn(*const MENUTEMPLATEW) -> HMENU;
pub type FnLoadMenuW = unsafe extern "system" fn(HINSTANCE, LPCWSTR) -> HMENU;
pub type FnLoadStringA = unsafe extern "system" fn(HINSTANCE, UINT, LPSTR, c_int) -> c_int;
pub type FnLoadStringW = unsafe extern "system" fn(HINSTANCE, UINT, LPWSTR, c_int) -> c_int;
pub type FnLockSetForegroundWindow = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnLockWindowUpdate = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnLockWorkStation = unsafe extern "system" fn() -> BOOL;
pub type FnLogicalToPhysicalPoint = unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnLogicalToPhysicalPointForPerMonitorDPI =
    unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnLookupIconIdFromDirectory = unsafe extern "system" fn(PBYTE, BOOL) -> c_int;
pub type FnLookupIconIdFromDirectoryEx =
    unsafe extern "system" fn(PBYTE, BOOL, c_int, c_int, UINT) -> c_int;
pub type FnMapDialogRect = unsafe extern "system" fn(HWND, LPRECT) -> BOOL;
pub type FnMapVirtualKeyA = unsafe extern "system" fn(UINT, UINT) -> UINT;
pub type FnMapVirtualKeyExA = unsafe extern "system" fn(UINT, UINT, HKL) -> UINT;
pub type FnMapVirtualKeyExW = unsafe extern "system" fn(UINT, UINT, HKL) -> UINT;
pub type FnMapVirtualKeyW = unsafe extern "system" fn(UINT, UINT) -> UINT;
pub type FnMapWindowPoints = unsafe extern "system" fn(HWND, HWND, LPPOINT, UINT) -> c_int;
pub type FnMenuItemFromPoint = unsafe extern "system" fn(HWND, HMENU, POINT) -> c_int;
pub type FnMessageBeep = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnMessageBoxA = unsafe extern "system" fn(HWND, LPCSTR, LPCSTR, UINT) -> c_int;
pub type FnMessageBoxExA = unsafe extern "system" fn(HWND, LPCSTR, LPCSTR, UINT, WORD) -> c_int;
pub type FnMessageBoxExW = unsafe extern "system" fn(HWND, LPCWSTR, LPCWSTR, UINT, WORD) -> c_int;
pub type FnMessageBoxIndirectA = unsafe extern "system" fn(*const MSGBOXPARAMSA) -> c_int;
pub type FnMessageBoxIndirectW = unsafe extern "system" fn(*const MSGBOXPARAMSW) -> c_int;
pub type FnMessageBoxW = unsafe extern "system" fn(HWND, LPCWSTR, LPCWSTR, UINT) -> c_int;
pub type FnModifyMenuA = unsafe extern "system" fn(HMENU, UINT, UINT, UINT_PTR, LPCSTR) -> BOOL;
pub type FnModifyMenuW = unsafe extern "system" fn(HMENU, UINT, UINT, UINT_PTR, LPCWSTR) -> BOOL;
pub type FnMonitorFromPoint = unsafe extern "system" fn(POINT, DWORD) -> HMONITOR;
pub type FnMonitorFromRect = unsafe extern "system" fn(LPCRECT, DWORD) -> HMONITOR;
pub type FnMonitorFromWindow = unsafe extern "system" fn(HWND, DWORD) -> HMONITOR;
pub type FnMoveWindow = unsafe extern "system" fn(HWND, c_int, c_int, c_int, c_int, BOOL) -> BOOL;
pub type FnMsgWaitForMultipleObjects =
    unsafe extern "system" fn(DWORD, *const HANDLE, BOOL, DWORD, DWORD) -> DWORD;
pub type FnMsgWaitForMultipleObjectsEx =
    unsafe extern "system" fn(DWORD, *const HANDLE, DWORD, DWORD, DWORD) -> DWORD;
pub type FnNotifyWinEvent = unsafe extern "system" fn(DWORD, HWND, LONG, LONG) -> ();
pub type FnOemKeyScan = unsafe extern "system" fn(WORD) -> DWORD;
pub type FnOemToCharA = unsafe extern "system" fn(LPCSTR, LPSTR) -> BOOL;
pub type FnOemToCharBuffA = unsafe extern "system" fn(LPCSTR, LPSTR, DWORD) -> BOOL;
pub type FnOemToCharBuffW = unsafe extern "system" fn(LPCSTR, LPWSTR, DWORD) -> BOOL;
pub type FnOemToCharW = unsafe extern "system" fn(LPCSTR, LPWSTR) -> BOOL;
pub type FnOffsetRect = unsafe extern "system" fn(LPRECT, c_int, c_int) -> BOOL;
pub type FnOpenClipboard = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnOpenDesktopA = unsafe extern "system" fn(LPCSTR, DWORD, BOOL, ACCESS_MASK) -> HDESK;
pub type FnOpenDesktopW = unsafe extern "system" fn(LPCWSTR, DWORD, BOOL, ACCESS_MASK) -> HDESK;
pub type FnOpenIcon = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnOpenInputDesktop = unsafe extern "system" fn(DWORD, BOOL, ACCESS_MASK) -> HDESK;
pub type FnOpenWindowStationA = unsafe extern "system" fn(LPCSTR, BOOL, ACCESS_MASK) -> HWINSTA;
pub type FnOpenWindowStationW = unsafe extern "system" fn(LPCWSTR, BOOL, ACCESS_MASK) -> HWINSTA;
pub type FnPackDDElParam = unsafe extern "system" fn(UINT, UINT_PTR, UINT_PTR) -> LPARAM;
pub type FnPackTouchHitTestingProximityEvaluation = unsafe extern "system" fn(
    *const TOUCH_HIT_TESTING_INPUT,
    *const TOUCH_HIT_TESTING_PROXIMITY_EVALUATION,
) -> LRESULT;
pub type FnPaintDesktop = unsafe extern "system" fn(HDC) -> BOOL;
pub type FnPeekMessageA = unsafe extern "system" fn(LPMSG, HWND, UINT, UINT, UINT) -> BOOL;
pub type FnPeekMessageW = unsafe extern "system" fn(LPMSG, HWND, UINT, UINT, UINT) -> BOOL;
pub type FnPhysicalToLogicalPoint = unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnPhysicalToLogicalPointForPerMonitorDPI =
    unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnPostMessageA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnPostMessageW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnPostQuitMessage = unsafe extern "system" fn(c_int) -> ();
pub type FnPostThreadMessageA = unsafe extern "system" fn(DWORD, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnPostThreadMessageW = unsafe extern "system" fn(DWORD, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnPrintWindow = unsafe extern "system" fn(HWND, HDC, UINT) -> BOOL;
pub type FnPtInRect = unsafe extern "system" fn(*const RECT, POINT) -> BOOL;
pub type FnRealChildWindowFromPoint = unsafe extern "system" fn(HWND, POINT) -> HWND;
pub type FnRealGetWindowClassA = unsafe extern "system" fn(HWND, LPSTR, UINT) -> UINT;
pub type FnRealGetWindowClassW = unsafe extern "system" fn(HWND, LPWSTR, UINT) -> UINT;
pub type FnRedrawWindow = unsafe extern "system" fn(HWND, *const RECT, HRGN, UINT) -> BOOL;
pub type FnRegisterClassA = unsafe extern "system" fn(*const WNDCLASSA) -> ATOM;
pub type FnRegisterClassExA = unsafe extern "system" fn(*const WNDCLASSEXA) -> ATOM;
pub type FnRegisterClassExW = unsafe extern "system" fn(*const WNDCLASSEXW) -> ATOM;
pub type FnRegisterClassW = unsafe extern "system" fn(*const WNDCLASSW) -> ATOM;
pub type FnRegisterClipboardFormatA = unsafe extern "system" fn(LPCSTR) -> UINT;
pub type FnRegisterClipboardFormatW = unsafe extern "system" fn(LPCWSTR) -> UINT;
pub type FnRegisterDeviceNotificationA =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD) -> HDEVNOTIFY;
pub type FnRegisterDeviceNotificationW =
    unsafe extern "system" fn(HANDLE, LPVOID, DWORD) -> HDEVNOTIFY;
pub type FnRegisterHotKey = unsafe extern "system" fn(HWND, c_int, UINT, UINT) -> BOOL;
pub type FnRegisterPointerInputTarget = unsafe extern "system" fn(HWND, POINTER_INPUT_TYPE) -> BOOL;
pub type FnRegisterPointerInputTargetEx =
    unsafe extern "system" fn(HWND, POINTER_INPUT_TYPE, BOOL) -> BOOL;
pub type FnRegisterPowerSettingNotification =
    unsafe extern "system" fn(HANDLE, LPCGUID, DWORD) -> HPOWERNOTIFY;
pub type FnRegisterRawInputDevices =
    unsafe extern "system" fn(PCRAWINPUTDEVICE, UINT, UINT) -> BOOL;
pub type FnRegisterShellHookWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnRegisterSuspendResumeNotification =
    unsafe extern "system" fn(HANDLE, DWORD) -> HPOWERNOTIFY;
pub type FnRegisterTouchHitTestingWindow = unsafe extern "system" fn(HWND, ULONG) -> BOOL;
pub type FnRegisterTouchWindow = unsafe extern "system" fn(HWND, ULONG) -> BOOL;
pub type FnRegisterWindowMessageA = unsafe extern "system" fn(LPCSTR) -> UINT;
pub type FnRegisterWindowMessageW = unsafe extern "system" fn(LPCWSTR) -> UINT;
pub type FnReleaseCapture = unsafe extern "system" fn() -> BOOL;
pub type FnReleaseDC = unsafe extern "system" fn(HWND, HDC) -> c_int;
pub type FnRemoveClipboardFormatListener = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnRemoveMenu = unsafe extern "system" fn(HMENU, UINT, UINT) -> BOOL;
pub type FnRemovePropA = unsafe extern "system" fn(HWND, LPCSTR) -> HANDLE;
pub type FnRemovePropW = unsafe extern "system" fn(HWND, LPCWSTR) -> HANDLE;
pub type FnReplyMessage = unsafe extern "system" fn(LRESULT) -> BOOL;
pub type FnScreenToClient = unsafe extern "system" fn(HWND, LPPOINT) -> BOOL;
pub type FnScrollDC =
    unsafe extern "system" fn(HDC, c_int, c_int, *const RECT, *const RECT, HRGN, LPRECT) -> BOOL;
pub type FnScrollWindow =
    unsafe extern "system" fn(HWND, c_int, c_int, *const RECT, *const RECT) -> BOOL;
pub type FnScrollWindowEx = unsafe extern "system" fn(
    HWND,
    c_int,
    c_int,
    *const RECT,
    *const RECT,
    HRGN,
    LPRECT,
    UINT,
) -> c_int;
pub type FnSendDlgItemMessageA =
    unsafe extern "system" fn(HWND, c_int, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnSendDlgItemMessageW =
    unsafe extern "system" fn(HWND, c_int, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnSendInput = unsafe extern "system" fn(UINT, LPINPUT, c_int) -> UINT;
pub type FnSendMessageA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnSendMessageCallbackA =
    unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM, SENDASYNCPROC, ULONG_PTR) -> BOOL;
pub type FnSendMessageCallbackW =
    unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM, SENDASYNCPROC, ULONG_PTR) -> BOOL;
pub type FnSendMessageTimeoutA =
    unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM, UINT, UINT, PDWORD_PTR) -> LRESULT;
pub type FnSendMessageTimeoutW =
    unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM, UINT, UINT, PDWORD_PTR) -> LRESULT;
pub type FnSendMessageW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT;
pub type FnSendNotifyMessageA = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnSendNotifyMessageW = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
pub type FnSetActiveWindow = unsafe extern "system" fn(HWND) -> HWND;
pub type FnSetCapture = unsafe extern "system" fn(HWND) -> HWND;
pub type FnSetCaretBlinkTime = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnSetCaretPos = unsafe extern "system" fn(c_int, c_int) -> BOOL;
pub type FnSetClassLongA = unsafe extern "system" fn(HWND, c_int, LONG) -> DWORD;
pub type FnSetClassLongPtrA = unsafe extern "system" fn(HWND, c_int, LONG_PTR) -> ULONG_PTR;
pub type FnSetClassLongPtrW = unsafe extern "system" fn(HWND, c_int, LONG_PTR) -> ULONG_PTR;
pub type FnSetClassLongW = unsafe extern "system" fn(HWND, c_int, LONG) -> DWORD;
pub type FnSetClassWord = unsafe extern "system" fn(HWND, c_int, WORD) -> WORD;
pub type FnSetClipboardData = unsafe extern "system" fn(UINT, HANDLE) -> HANDLE;
pub type FnSetClipboardViewer = unsafe extern "system" fn(HWND) -> HWND;
pub type FnSetCoalescableTimer =
    unsafe extern "system" fn(HWND, UINT_PTR, UINT, TIMERPROC, ULONG) -> UINT_PTR;
pub type FnSetCursor = unsafe extern "system" fn(HCURSOR) -> HCURSOR;
pub type FnSetCursorPos = unsafe extern "system" fn(c_int, c_int) -> BOOL;
pub type FnSetDialogControlDpiChangeBehavior = unsafe extern "system" fn(
    HWND,
    DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS,
    DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS,
) -> BOOL;
pub type FnSetDialogDpiChangeBehavior = unsafe extern "system" fn(
    HWND,
    DIALOG_DPI_CHANGE_BEHAVIORS,
    DIALOG_DPI_CHANGE_BEHAVIORS,
) -> BOOL;
pub type FnSetDlgItemInt = unsafe extern "system" fn(HWND, c_int, UINT, BOOL) -> BOOL;
pub type FnSetDlgItemTextA = unsafe extern "system" fn(HWND, c_int, LPCSTR) -> BOOL;
pub type FnSetDlgItemTextW = unsafe extern "system" fn(HWND, c_int, LPCWSTR) -> BOOL;
pub type FnSetDoubleClickTime = unsafe extern "system" fn(UINT) -> BOOL;
pub type FnSetFocus = unsafe extern "system" fn(HWND) -> HWND;
pub type FnSetForegroundWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnSetKeyboardState = unsafe extern "system" fn(LPBYTE) -> BOOL;
pub type FnSetLastErrorEx = unsafe extern "system" fn(DWORD, DWORD) -> ();
pub type FnSetLayeredWindowAttributes =
    unsafe extern "system" fn(HWND, COLORREF, BYTE, DWORD) -> BOOL;
pub type FnSetMenu = unsafe extern "system" fn(HWND, HMENU) -> BOOL;
pub type FnSetMenuContextHelpId = unsafe extern "system" fn(HMENU, DWORD) -> BOOL;
pub type FnSetMenuDefaultItem = unsafe extern "system" fn(HMENU, UINT, UINT) -> BOOL;
pub type FnSetMenuInfo = unsafe extern "system" fn(HMENU, LPCMENUINFO) -> BOOL;
pub type FnSetMenuItemBitmaps =
    unsafe extern "system" fn(HMENU, UINT, UINT, HBITMAP, HBITMAP) -> BOOL;
pub type FnSetMenuItemInfoA =
    unsafe extern "system" fn(HMENU, UINT, BOOL, LPCMENUITEMINFOA) -> BOOL;
pub type FnSetMenuItemInfoW =
    unsafe extern "system" fn(HMENU, UINT, BOOL, LPCMENUITEMINFOW) -> BOOL;
pub type FnSetMessageExtraInfo = unsafe extern "system" fn(LPARAM) -> LPARAM;
pub type FnSetMessageQueue = unsafe extern "system" fn(c_int) -> BOOL;
pub type FnSetParent = unsafe extern "system" fn(HWND, HWND) -> HWND;
pub type FnSetPhysicalCursorPos = unsafe extern "system" fn(c_int, c_int) -> BOOL;
pub type FnSetProcessDPIAware = unsafe extern "system" fn() -> BOOL;
pub type FnSetProcessDefaultLayout = unsafe extern "system" fn(DWORD) -> BOOL;
pub type FnSetProcessDpiAwarenessContext = unsafe extern "system" fn(DPI_AWARENESS_CONTEXT) -> BOOL;
pub type FnSetProcessWindowStation = unsafe extern "system" fn(HWINSTA) -> BOOL;
pub type FnSetPropA = unsafe extern "system" fn(HWND, LPCSTR, HANDLE) -> BOOL;
pub type FnSetPropW = unsafe extern "system" fn(HWND, LPCWSTR, HANDLE) -> BOOL;
pub type FnSetRect = unsafe extern "system" fn(LPRECT, c_int, c_int, c_int, c_int) -> BOOL;
pub type FnSetRectEmpty = unsafe extern "system" fn(LPRECT) -> BOOL;
pub type FnSetScrollInfo = unsafe extern "system" fn(HWND, c_int, *const SCROLLINFO, BOOL) -> c_int;
pub type FnSetScrollPos = unsafe extern "system" fn(HWND, c_int, c_int, BOOL) -> c_int;
pub type FnSetScrollRange = unsafe extern "system" fn(HWND, c_int, c_int, c_int, BOOL) -> BOOL;
pub type FnSetSysColors = unsafe extern "system" fn(c_int, *const INT, *const COLORREF) -> BOOL;
pub type FnSetSystemCursor = unsafe extern "system" fn(HCURSOR, DWORD) -> BOOL;
pub type FnSetThreadDesktop = unsafe extern "system" fn(HDESK) -> BOOL;
pub type FnSetThreadDpiAwarenessContext =
    unsafe extern "system" fn(DPI_AWARENESS_CONTEXT) -> DPI_AWARENESS_CONTEXT;
pub type FnSetThreadDpiHostingBehavior =
    unsafe extern "system" fn(DPI_HOSTING_BEHAVIOR) -> DPI_HOSTING_BEHAVIOR;
pub type FnSetTimer = unsafe extern "system" fn(HWND, UINT_PTR, UINT, TIMERPROC) -> UINT_PTR;
pub type FnSetUserObjectInformationA =
    unsafe extern "system" fn(HANDLE, c_int, PVOID, DWORD) -> BOOL;
pub type FnSetUserObjectInformationW =
    unsafe extern "system" fn(HANDLE, c_int, PVOID, DWORD) -> BOOL;
pub type FnSetUserObjectSecurity =
    unsafe extern "system" fn(HANDLE, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR) -> BOOL;
pub type FnSetWinEventHook = unsafe extern "system" fn(
    DWORD,
    DWORD,
    HMODULE,
    WINEVENTPROC,
    DWORD,
    DWORD,
    DWORD,
) -> HWINEVENTHOOK;
pub type FnSetWindowContextHelpId = unsafe extern "system" fn(HWND, DWORD) -> BOOL;
pub type FnSetWindowDisplayAffinity = unsafe extern "system" fn(HWND, DWORD) -> BOOL;
pub type FnSetWindowFeedbackSetting =
    unsafe extern "system" fn(HWND, FEEDBACK_TYPE, DWORD, UINT32, *const VOID) -> BOOL;
pub type FnSetWindowLongA = unsafe extern "system" fn(HWND, c_int, LONG) -> LONG;
pub type FnSetWindowLongPtrA = unsafe extern "system" fn(HWND, c_int, LONG_PTR) -> LONG_PTR;
pub type FnSetWindowLongPtrW = unsafe extern "system" fn(HWND, c_int, LONG_PTR) -> LONG_PTR;
pub type FnSetWindowLongW = unsafe extern "system" fn(HWND, c_int, LONG) -> LONG;
pub type FnSetWindowPlacement = unsafe extern "system" fn(HWND, *const WINDOWPLACEMENT) -> BOOL;
pub type FnSetWindowPos =
    unsafe extern "system" fn(HWND, HWND, c_int, c_int, c_int, c_int, UINT) -> BOOL;
pub type FnSetWindowRgn = unsafe extern "system" fn(HWND, HRGN, BOOL) -> c_int;
pub type FnSetWindowTextA = unsafe extern "system" fn(HWND, LPCSTR) -> BOOL;
pub type FnSetWindowTextW = unsafe extern "system" fn(HWND, LPCWSTR) -> BOOL;
pub type FnSetWindowWord = unsafe extern "system" fn(HWND, c_int, WORD) -> WORD;
pub type FnSetWindowsHookA = unsafe extern "system" fn(c_int, HOOKPROC) -> HHOOK;
pub type FnSetWindowsHookExA =
    unsafe extern "system" fn(c_int, HOOKPROC, HINSTANCE, DWORD) -> HHOOK;
pub type FnSetWindowsHookExW =
    unsafe extern "system" fn(c_int, HOOKPROC, HINSTANCE, DWORD) -> HHOOK;
pub type FnSetWindowsHookW = unsafe extern "system" fn(c_int, HOOKPROC) -> HHOOK;
pub type FnShowCaret = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnShowCursor = unsafe extern "system" fn(BOOL) -> c_int;
pub type FnShowOwnedPopups = unsafe extern "system" fn(HWND, BOOL) -> BOOL;
pub type FnShowScrollBar = unsafe extern "system" fn(HWND, c_int, BOOL) -> BOOL;
pub type FnShowWindow = unsafe extern "system" fn(HWND, c_int) -> BOOL;
pub type FnShowWindowAsync = unsafe extern "system" fn(HWND, c_int) -> BOOL;
pub type FnShutdownBlockReasonCreate = unsafe extern "system" fn(HWND, LPCWSTR) -> BOOL;
pub type FnShutdownBlockReasonDestroy = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnShutdownBlockReasonQuery = unsafe extern "system" fn(HWND, LPWSTR, *mut DWORD) -> BOOL;
pub type FnSkipPointerFrameMessages = unsafe extern "system" fn(UINT32) -> BOOL;
pub type FnSubtractRect = unsafe extern "system" fn(LPRECT, *const RECT, *const RECT) -> BOOL;
pub type FnSwapMouseButton = unsafe extern "system" fn(BOOL) -> BOOL;
pub type FnSwitchDesktop = unsafe extern "system" fn(HDESK) -> BOOL;
pub type FnSwitchToThisWindow = unsafe extern "system" fn(HWND, BOOL) -> ();
pub type FnSystemParametersInfoA = unsafe extern "system" fn(UINT, UINT, PVOID, UINT) -> BOOL;
pub type FnSystemParametersInfoForDpi =
    unsafe extern "system" fn(UINT, UINT, PVOID, UINT, UINT) -> BOOL;
pub type FnSystemParametersInfoW = unsafe extern "system" fn(UINT, UINT, PVOID, UINT) -> BOOL;
pub type FnTabbedTextOutA =
    unsafe extern "system" fn(HDC, c_int, c_int, LPCSTR, c_int, c_int, *const INT, c_int) -> LONG;
pub type FnTabbedTextOutW =
    unsafe extern "system" fn(HDC, c_int, c_int, LPCWSTR, c_int, c_int, *const INT, c_int) -> LONG;
pub type FnToAscii = unsafe extern "system" fn(UINT, UINT, *const BYTE, LPWORD, UINT) -> c_int;
pub type FnToAsciiEx =
    unsafe extern "system" fn(UINT, UINT, *const BYTE, LPWORD, UINT, HKL) -> c_int;
pub type FnToUnicode =
    unsafe extern "system" fn(UINT, UINT, *const BYTE, LPWSTR, c_int, UINT) -> c_int;
pub type FnToUnicodeEx =
    unsafe extern "system" fn(UINT, UINT, *const BYTE, LPWSTR, c_int, UINT, HKL) -> c_int;
pub type FnTrackMouseEvent = unsafe extern "system" fn(LPTRACKMOUSEEVENT) -> BOOL;
pub type FnTrackPopupMenu =
    unsafe extern "system" fn(HMENU, UINT, c_int, c_int, c_int, HWND, *const RECT) -> BOOL;
pub type FnTrackPopupMenuEx =
    unsafe extern "system" fn(HMENU, UINT, INT, INT, HWND, LPTPMPARAMS) -> BOOL;
pub type FnTranslateAcceleratorA = unsafe extern "system" fn(HWND, HACCEL, LPMSG) -> c_int;
pub type FnTranslateAcceleratorW = unsafe extern "system" fn(HWND, HACCEL, LPMSG) -> c_int;
pub type FnTranslateMessage = unsafe extern "system" fn(*const MSG) -> BOOL;
pub type FnUnhookWinEvent = unsafe extern "system" fn(HWINEVENTHOOK) -> BOOL;
pub type FnUnhookWindowsHook = unsafe extern "system" fn(c_int, HOOKPROC) -> BOOL;
pub type FnUnhookWindowsHookEx = unsafe extern "system" fn(HHOOK) -> BOOL;
pub type FnUnionRect = unsafe extern "system" fn(LPRECT, *const RECT, *const RECT) -> BOOL;
pub type FnUnloadKeyboardLayout = unsafe extern "system" fn(HKL) -> BOOL;
pub type FnUnpackDDElParam = unsafe extern "system" fn(UINT, LPARAM, PUINT_PTR, PUINT_PTR) -> BOOL;
pub type FnUnregisterClassA = unsafe extern "system" fn(LPCSTR, HINSTANCE) -> BOOL;
pub type FnUnregisterClassW = unsafe extern "system" fn(LPCWSTR, HINSTANCE) -> BOOL;
pub type FnUnregisterDeviceNotification = unsafe extern "system" fn(HDEVNOTIFY) -> BOOL;
pub type FnUnregisterHotKey = unsafe extern "system" fn(HWND, c_int) -> BOOL;
pub type FnUnregisterPointerInputTarget =
    unsafe extern "system" fn(HWND, POINTER_INPUT_TYPE) -> BOOL;
pub type FnUnregisterPointerInputTargetEx =
    unsafe extern "system" fn(HWND, POINTER_INPUT_TYPE) -> BOOL;
pub type FnUnregisterPowerSettingNotification = unsafe extern "system" fn(HPOWERNOTIFY) -> BOOL;
pub type FnUnregisterSuspendResumeNotification = unsafe extern "system" fn(HPOWERNOTIFY) -> BOOL;
pub type FnUnregisterTouchWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnUpdateLayeredWindow = unsafe extern "system" fn(
    HWND,
    HDC,
    *mut POINT,
    *mut SIZE,
    HDC,
    *mut POINT,
    COLORREF,
    *mut BLENDFUNCTION,
    DWORD,
) -> BOOL;
pub type FnUpdateLayeredWindowIndirect =
    unsafe extern "system" fn(HWND, *mut UPDATELAYEREDWINDOWINFO) -> BOOL;
pub type FnUpdateWindow = unsafe extern "system" fn(HWND) -> BOOL;
pub type FnUserHandleGrantAccess = unsafe extern "system" fn(HANDLE, HANDLE, BOOL) -> BOOL;
pub type FnValidateRect = unsafe extern "system" fn(HWND, *const RECT) -> BOOL;
pub type FnValidateRgn = unsafe extern "system" fn(HWND, HRGN) -> BOOL;
pub type FnVkKeyScanA = unsafe extern "system" fn(CHAR) -> SHORT;
pub type FnVkKeyScanExA = unsafe extern "system" fn(CHAR, HKL) -> SHORT;
pub type FnVkKeyScanExW = unsafe extern "system" fn(WCHAR, HKL) -> SHORT;
pub type FnVkKeyScanW = unsafe extern "system" fn(WCHAR) -> SHORT;
pub type FnWaitForInputIdle = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;
pub type FnWaitMessage = unsafe extern "system" fn() -> BOOL;
pub type FnWinHelpA = unsafe extern "system" fn(HWND, LPCSTR, UINT, ULONG_PTR) -> BOOL;
pub type FnWinHelpW = unsafe extern "system" fn(HWND, LPCWSTR, UINT, ULONG_PTR) -> BOOL;
pub type FnWindowFromDC = unsafe extern "system" fn(HDC) -> HWND;
pub type FnWindowFromPhysicalPoint = unsafe extern "system" fn(POINT) -> HWND;
pub type FnWindowFromPoint = unsafe extern "system" fn(POINT) -> HWND;
pub type Fnkeybd_event = unsafe extern "system" fn(BYTE, BYTE, DWORD, ULONG_PTR) -> ();
pub type Fnmouse_event = unsafe extern "system" fn(DWORD, DWORD, DWORD, DWORD, ULONG_PTR) -> ();
pub type FnwsprintfA = unsafe extern "system" fn(LPSTR, LPCSTR) -> c_int;
pub type FnwsprintfW = unsafe extern "system" fn(LPWSTR, LPCWSTR) -> c_int;
pub type FnwvsprintfA = unsafe extern "system" fn(LPSTR, LPCSTR, va_list) -> c_int;
pub type FnwvsprintfW = unsafe extern "system" fn(LPWSTR, LPCWSTR, va_list) -> c_int;
