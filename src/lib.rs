#[cfg(feature = "user32")]
pub mod user32;

#[cfg(feature = "advapi32")]
pub mod advapi32;

#[cfg(feature = "crypt32")]
pub mod crypt32;

#[cfg(feature = "kernel32")]
pub mod kernel32;

#[cfg(feature = "kernelbase")]
pub mod kernelbase;

#[cfg(feature = "winhttp")]
pub mod winhttp;

#[cfg(feature = "ntdll")]
pub mod ntdll;

pub mod types;
