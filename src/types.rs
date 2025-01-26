use winapi::shared::basetsd::DWORD64;
use winapi::shared::minwindef::{DWORD, WORD};
use winapi::shared::ntdef::{NTSTATUS, PUNICODE_STRING, UNICODE_STRING, USHORT};
use winapi::um::winnt::{CONTEXT_u, M128A, PWSTR};

pub enum NtStatus {
    NtSuccess(NTSTATUS),
    NtInformation(NTSTATUS),
    NtWarning(NTSTATUS),
    NtError(NTSTATUS),
}

pub trait StatusCheck {
    fn to_enum(&self) -> NtStatus;
}

impl StatusCheck for NTSTATUS {
    fn to_enum(&self) -> NtStatus {
        match (*self as u32) >> 30 {
            0 => NtStatus::NtSuccess(*self),
            1 => NtStatus::NtInformation(*self),
            2 => NtStatus::NtWarning(*self),
            3 => NtStatus::NtError(*self),
            _ => unreachable!(),
        }
    }
}

#[allow(non_camel_case_types)]
pub struct S_UNICODE_STRING {
    string: UNICODE_STRING,
    buffer: Vec<u16>,
}

impl S_UNICODE_STRING {
    pub fn new(s: &str) -> Self {
        let mut buffer: Vec<u16> = s.encode_utf16().collect();
        buffer.push(0);

        let string = UNICODE_STRING {
            Length: ((buffer.len() - 1) * 2) as USHORT,
            MaximumLength: (buffer.len() * 2) as USHORT,
            Buffer: buffer.as_ptr() as PWSTR,
        };

        Self { string, buffer }
    }

    pub unsafe fn as_ptr(&mut self) -> PUNICODE_STRING {
        &mut self.string
    }

    pub fn as_ref(&self) -> &UNICODE_STRING {
        &self.string
    }

    pub fn as_raw(&self) -> UNICODE_STRING {
        self.string
    }
}

#[repr(C, align(16))]
#[allow(non_snake_case)]
pub struct CONTEXT {
    pub P1Home: DWORD64,
    pub P2Home: DWORD64,
    pub P3Home: DWORD64,
    pub P4Home: DWORD64,
    pub P5Home: DWORD64,
    pub P6Home: DWORD64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
    pub EFlags: DWORD,
    pub Dr0: DWORD64,
    pub Dr1: DWORD64,
    pub Dr2: DWORD64,
    pub Dr3: DWORD64,
    pub Dr6: DWORD64,
    pub Dr7: DWORD64,
    pub Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    pub Rbx: DWORD64,
    pub Rsp: DWORD64,
    pub Rbp: DWORD64,
    pub Rsi: DWORD64,
    pub Rdi: DWORD64,
    pub R8: DWORD64,
    pub R9: DWORD64,
    pub R10: DWORD64,
    pub R11: DWORD64,
    pub R12: DWORD64,
    pub R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    pub u: CONTEXT_u,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: DWORD64,
    pub DebugControl: DWORD64,
    pub LastBranchToRip: DWORD64,
    pub LastBranchFromRip: DWORD64,
    pub LastExceptionToRip: DWORD64,
    pub LastExceptionFromRip: DWORD64,
}

#[allow(non_camel_case_types)]
pub type PCONTEXT = *mut CONTEXT;

#[allow(non_camel_case_types)]
pub type LPCONTEXT = PCONTEXT;
