use core::{ptr, slice};
use std::mem::{self, MaybeUninit};

use rust_win32error::Win32Error;
use winapi::{
    shared::minwindef::DWORD,
    um::{memoryapi::*, winnt::*},
};

use crate::ProcessRef;

#[derive(Debug)]
pub struct SharedMemory<'a> {
    ptr: *mut u8,
    process: ProcessRef<'a>,
    len: usize,
    is_owner: bool,
}

impl<'a> SharedMemory<'a> {
    pub fn allocate_local(len: usize) -> Result<Self, Win32Error> {
        Self::allocate(ProcessRef::current(), len)
    }
    pub fn allocate(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_with_options(process, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    }
    pub fn allocate_code(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_with_options(
            process,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }
    pub fn allocate_with_options(
        process: ProcessRef<'a>,
        len: usize,
        allocation_type: DWORD,
        protection: DWORD,
    ) -> Result<Self, Win32Error> {
        // TODO: use VirtualAlloc (non Ex) to allocate memory in the local process

        let ptr = unsafe {
            VirtualAllocEx(
                process.handle(),
                ptr::null_mut(),
                len,
                allocation_type,
                protection,
            )
        };
        return if ptr.is_null() {
            Err(Win32Error::new())
        } else {
            Ok(unsafe { Self::from_parts(ptr.cast(), process, len, true) })
        };
    }
    pub fn allocate_uninit_struct<T>(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate(process, mem::size_of::<T>())
    }
    pub fn allocate_struct<T: ?Sized>(process: ProcessRef<'a>, s: &T) -> Result<Self, Win32Error> {
        let buf = Self::allocate(process, mem::size_of_val(s))?;
        buf.write_struct(0, s)?;
        Ok(buf)
    }

    pub unsafe fn from_parts(
        ptr: *mut u8,
        process: ProcessRef<'a>,
        len: usize,
        is_owner: bool,
    ) -> Self {
        Self {
            ptr,
            process,
            len,
            is_owner,
        }
    }
    pub unsafe fn local_from_parts(ptr: *mut u8, len: usize, owned: bool) -> Self {
        unsafe { Self::from_parts(ptr, ProcessRef::current(), len, owned) }
    }

    pub unsafe fn clone_as_unowned(&self) -> Self {
        unsafe { Self::from_parts(self.ptr, self.process(), self.len, false) }
    }

    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }
    pub fn process(&self) -> ProcessRef<'a> {
        self.process
    }
    pub fn is_owner(&self) -> bool {
        self.is_owner
    }
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), Win32Error> {
        if offset + buf.len() > self.len {
            panic!("read out of bounds");
        }

        let mut bytes_read = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.process.handle(),
                self.ptr.add(offset).cast(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut bytes_read,
            )
        };
        if res == 0 {
            Err(Win32Error::new())
        } else {
            assert_eq!(bytes_read, buf.len());
            Ok(())
        }
    }

    pub unsafe fn read_struct<T>(&self, offset: usize) -> Result<T, Win32Error> {
        let mut uninit_value = MaybeUninit::uninit();
        self.read(offset, unsafe {
            slice::from_raw_parts_mut(uninit_value.as_mut_ptr() as *mut u8, mem::size_of::<T>())
        })?;
        Ok(unsafe { uninit_value.assume_init() })
    }

    pub fn write(&self, offset: usize, buf: &[u8]) -> Result<(), Win32Error> {
        if offset + buf.len() > self.len {
            panic!("write out of bounds");
        }

        let mut bytes_written = 0;
        let res = unsafe {
            WriteProcessMemory(
                self.process.handle(),
                self.ptr.add(offset).cast(),
                buf.as_ptr().cast(),
                buf.len(),
                &mut bytes_written,
            )
        };
        if res == 0 {
            Err(Win32Error::new())
        } else {
            assert_eq!(bytes_written, buf.len());
            Ok(())
        }
    }

    pub fn write_struct<T: ?Sized>(&self, offset: usize, s: &T) -> Result<(), Win32Error> {
        self.write(offset, unsafe {
            slice::from_raw_parts(s as *const T as *const u8, mem::size_of_val(s))
        })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn into_parts(mut self) -> (*mut u8, usize, bool) {
        let was_owner = self.is_owner;
        self.is_owner = false;
        (self.as_mut_ptr(), self.len(), was_owner)
    }

    pub fn leak(self) {
        self.into_parts();
    }

    pub fn free(mut self) -> Result<(), Win32Error> {
        unsafe { self._free() }
    }
    unsafe fn _free(&mut self) -> Result<(), Win32Error> {
        let result = unsafe {
            VirtualFreeEx(
                self.process().handle(),
                self.as_mut_ptr().cast(),
                self.len(),
                MEM_RELEASE,
            )
        };

        self.is_owner = false;

        if result != 0 {
            Err(Win32Error::new())
        } else {
            Ok(())
        }
    }
}

impl Drop for SharedMemory<'_> {
    fn drop(&mut self) {
        if self.is_owner() {
            let _ = unsafe { self._free() };
        }
    }
}
