use winapi::shared::ntdef::{NTSTATUS, PUNICODE_STRING, UNICODE_STRING, USHORT};
use winapi::um::winnt::PWSTR;

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
