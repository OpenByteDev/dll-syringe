#![allow(unused, clippy::upper_case_acronyms)]

pub type BOOL = core::ffi::c_int;
pub type DWORD = core::ffi::c_uint;
pub type HINSTANCE__ = core::ffi::c_void;
pub const MAX_PATH: usize = windows_sys::Win32::Foundation::MAX_PATH as _;
