use winapi::shared::ntdef::NTSTATUS;

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
        match *self >> 30 {
            0 if *self > 0 => NtStatus::NtSuccess(*self),
            1 => NtStatus::NtInformation(*self),
            2 => NtStatus::NtWarning(*self),
            3 => NtStatus::NtError(*self),
            _ => unreachable!(),
        }
    }
}
