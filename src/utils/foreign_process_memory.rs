use std::{
    mem::{self, MaybeUninit},
    ptr,
};

use rust_win32error::Win32Error;
use widestring::U16CStr;
use winapi::um::{
    memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
    winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE},
};

use crate::ProcessRef;

pub(crate) struct ForeignProcessWideString<'a> {
    process: ProcessRef<'a>,
    ptr: *mut winapi::ctypes::c_void,
    byte_count: usize,
}

impl<'a> ForeignProcessWideString<'a> {
    pub fn allocate_in_process(
        process: ProcessRef<'a>,
        str: impl AsRef<U16CStr>,
    ) -> Result<Self, Win32Error> {
        let str = str.as_ref();
        let str_byte_count = str.as_slice_with_nul().len() * mem::size_of::<u16>();

        let remote_string_ptr = unsafe {
            VirtualAllocEx(
                process.handle(),
                ptr::null_mut(),
                str_byte_count,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_string_ptr.is_null() {
            return Err(Win32Error::new());
        }

        let mut bytes_written = MaybeUninit::uninit();
        let result = unsafe {
            WriteProcessMemory(
                process.handle(),
                remote_string_ptr,
                str.as_ptr().cast(),
                str_byte_count,
                bytes_written.as_mut_ptr(),
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        assert_eq!(unsafe { bytes_written.assume_init() }, str_byte_count);

        Ok(Self {
            process,
            ptr: remote_string_ptr.cast(),
            byte_count: str_byte_count,
        })
    }

    #[allow(dead_code)]
    pub fn as_ptr(&mut self) -> *const winapi::ctypes::c_void {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut winapi::ctypes::c_void {
        self.ptr
    }
}

impl<'a> Drop for ForeignProcessWideString<'a> {
    fn drop(&mut self) {
        unsafe {
            VirtualFreeEx(
                self.process.handle(),
                self.as_mut_ptr(),
                self.byte_count,
                MEM_RELEASE,
            );
        }
    }
}
