use std::{
    io,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::{Deref, DerefMut, RangeBounds},
    os::windows::prelude::AsRawHandle,
    ptr, slice,
};

use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::{
            ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx,
            WriteProcessMemory,
        },
        processthreadsapi::FlushInstructionCache,
        sysinfoapi::GetSystemInfo,
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
    },
};

use crate::{
    process::{BorrowedProcess, Process},
    utils,
};

/// A owned buffer in the memory space of a (remote) process.
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "process-memory")))]
#[derive(Debug)]
pub struct ProcessMemoryBuffer<'a>(ProcessMemorySlice<'a>);

impl<'a> Deref for ProcessMemoryBuffer<'a> {
    type Target = ProcessMemorySlice<'a>;

    fn deref(&self) -> &ProcessMemorySlice<'a> {
        &self.0
    }
}
impl<'a> DerefMut for ProcessMemoryBuffer<'a> {
    fn deref_mut(&mut self) -> &mut ProcessMemorySlice<'a> {
        &mut self.0
    }
}
impl<'a> AsRef<ProcessMemorySlice<'a>> for ProcessMemoryBuffer<'a> {
    fn as_ref(&self) -> &ProcessMemorySlice<'a> {
        self.deref()
    }
}
impl<'a> AsMut<ProcessMemorySlice<'a>> for ProcessMemoryBuffer<'a> {
    fn as_mut(&mut self) -> &mut ProcessMemorySlice<'a> {
        self.deref_mut()
    }
}

impl<'a> ProcessMemoryBuffer<'a> {
    /// Allocates a new buffer of the given length in the given process. Both data and code can be stored in the buffer.
    pub fn allocate(process: BorrowedProcess<'a>, len: usize) -> Result<Self, io::Error> {
        Self::allocate_code(process, len)
    }
    /// Allocates a new buffer with the size of a memory page in the given process.
    pub fn allocate_page(process: BorrowedProcess<'a>) -> Result<Self, io::Error> {
        Self::allocate_code(process, Self::os_page_size())
    }
    /// Allocates a new data buffer of the given length in the given process.
    pub fn allocate_data(process: BorrowedProcess<'a>, len: usize) -> Result<Self, io::Error> {
        Self::allocate_with_options(process, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    }
    /// Allocates a new data buffer with the size of a memory page in the given process.
    pub fn allocate_data_page(process: BorrowedProcess<'a>) -> Result<Self, io::Error> {
        Self::allocate_data(process, Self::os_page_size())
    }
    /// Allocates a new codea buffer of the given length in the given process.
    pub fn allocate_code(process: BorrowedProcess<'a>, len: usize) -> Result<Self, io::Error> {
        Self::allocate_with_options(
            process,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }
    /// Allocates a new code buffer with the size of a memory page in the given process.
    pub fn allocate_code_page(process: BorrowedProcess<'a>) -> Result<Self, io::Error> {
        Self::allocate_code(process, Self::os_page_size())
    }
    fn allocate_with_options(
        process: BorrowedProcess<'a>,
        len: usize,
        allocation_type: DWORD,
        protection: DWORD,
    ) -> Result<Self, io::Error> {
        let ptr = if process.is_current() {
            unsafe { VirtualAlloc(ptr::null_mut(), len, allocation_type, protection) }
        } else {
            unsafe {
                VirtualAllocEx(
                    process.as_raw_handle(),
                    ptr::null_mut(),
                    len,
                    allocation_type,
                    protection,
                )
            }
        };

        return if ptr.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { Self::from_raw_parts(ptr.cast(), len, process) })
        };
    }

    /// Allocates a new buffer with enough space to store a value of type `T` in the given process.
    pub fn allocate_for<T>(process: BorrowedProcess<'a>) -> Result<Self, io::Error> {
        Self::allocate_data(process, mem::size_of::<T>())
    }

    /// Allocates a new buffer with enough space to store a value of type `T` in the given process.
    pub fn allocate_and_write<T: ?Sized>(
        process: BorrowedProcess<'a>,
        s: &T,
    ) -> Result<Self, io::Error> {
        let buf = Self::allocate_data(process, mem::size_of_val(s))?;
        buf.write_struct(0, s)?;
        Ok(buf)
    }

    /// Constructs a new buffer from the given raw parts.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory
    /// - is valid
    /// - was allocated using [`VirtualAlloc`] or [`VirtualAllocEx`]
    /// - can be deallocated using [`VirtualFree`] or [`VirtualFreeEx`]
    /// - can be read using [`ReadProcessMemory`]
    /// - can be written to using [`WriteProcessMemory`]
    /// - will not be deallocated by other code
    pub const unsafe fn from_raw_parts(
        ptr: *mut u8,
        len: usize,
        process: BorrowedProcess<'a>,
    ) -> Self {
        Self(unsafe { ProcessMemorySlice::from_raw_parts(ptr, len, process) })
    }

    /// Constructs a new slice spanning the whole buffer.
    #[must_use]
    pub fn as_slice(&self) -> &ProcessMemorySlice<'a> {
        self.as_ref()
    }

    /// Constructs a new mutable slice spanning the whole buffer.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut ProcessMemorySlice<'a> {
        self.as_mut()
    }

    /// Frees the buffer.
    pub fn free(mut self) -> Result<(), (Self, io::Error)> {
        unsafe { self._free() }.map_err(|e| (self, e))
    }
    unsafe fn _free(&mut self) -> Result<(), io::Error> {
        let result = if self.is_local() {
            unsafe { VirtualFree(self.as_ptr().cast(), self.len(), MEM_RELEASE) }
        } else {
            unsafe {
                VirtualFreeEx(
                    self.process.as_raw_handle(),
                    self.as_ptr().cast(),
                    self.len(),
                    MEM_RELEASE,
                )
            }
        };

        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Returns the memory page size of the operating system.
    #[must_use]
    pub fn os_page_size() -> usize {
        let mut system_info = MaybeUninit::uninit();
        unsafe { GetSystemInfo(system_info.as_mut_ptr()) };
        unsafe { system_info.assume_init() }.dwPageSize as usize
    }
}

impl Drop for ProcessMemoryBuffer<'_> {
    fn drop(&mut self) {
        let result = unsafe { self._free() };
        debug_assert!(
            result.is_ok(),
            "Failed to free process memory buffer: {:?}",
            result
        );
    }
}

/// A unowned slice of a buffer in the memory space of a (remote) process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemorySlice<'a> {
    process: BorrowedProcess<'a>,
    ptr: *mut u8,
    len: usize,
    data: PhantomData<&'a [u8]>,
}

impl<'a> ProcessMemorySlice<'a> {
    /// Constructs a new slice from the given raw parts.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory
    /// - is valid
    /// - was allocated using [`VirtualAlloc`] or [`VirtualAllocEx`]
    /// - can be read using [`ReadProcessMemory`]
    /// - can be written to using [`WriteProcessMemory`]
    /// - will live as long as the slice is used
    pub const unsafe fn from_raw_parts(
        ptr: *mut u8,
        len: usize,
        process: BorrowedProcess<'a>,
    ) -> Self {
        Self {
            ptr,
            len,
            process,
            data: PhantomData,
        }
    }

    /// Returns whether the memory is allocated in the current process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }

    /// Returns whether the memory is allocated in another process.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    /// Returns the process the buffer is allocated in.
    #[must_use]
    pub const fn process(&self) -> BorrowedProcess<'a> {
        self.process
    }

    /// Returns the length of the buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the contents of this buffer starting from the given offset to the given local buffer.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the given buffer length exceeds this buffer's length.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), io::Error> {
        assert!(offset + buf.len() <= self.len, "read out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
            }
            return Ok(());
        }

        let mut bytes_read = 0;
        let result = unsafe {
            ReadProcessMemory(
                self.process.as_raw_handle(),
                self.ptr.add(offset).cast(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut bytes_read,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            assert_eq!(bytes_read, buf.len());
            Ok(())
        }
    }

    /// Reads a value of type `T` from this buffer starting from the given offset.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the size of the value exceeds this buffer's length.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains a valid instance of type `T` at the given offset.
    pub unsafe fn read_struct<T>(&self, offset: usize) -> Result<T, io::Error> {
        let mut uninit_value = MaybeUninit::<T>::uninit();
        self.read(offset, unsafe {
            slice::from_raw_parts_mut(uninit_value.as_mut_ptr().cast(), mem::size_of::<T>())
        })?;
        Ok(unsafe { uninit_value.assume_init() })
    }

    /// Copies the contents of the given local buffer to this buffer at the given offset.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the size of the local buffer exceeds this buffer's length.
    pub fn write(&self, offset: usize, buf: &[u8]) -> Result<(), io::Error> {
        assert!(offset + buf.len() <= self.len, "write out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy(buf.as_ptr(), self.ptr.add(offset), buf.len());
            }
            return Ok(());
        }

        let mut bytes_written = 0;
        let result = unsafe {
            WriteProcessMemory(
                self.process.as_raw_handle(),
                self.ptr.add(offset).cast(),
                buf.as_ptr().cast(),
                buf.len(),
                &mut bytes_written,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            assert_eq!(bytes_written, buf.len());
            Ok(())
        }
    }

    /// Writes a value of type `T` to this buffer at the given offset.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the given buffer length exceeds this buffer's length.
    pub fn write_struct<T: ?Sized>(&self, offset: usize, s: &T) -> Result<(), io::Error> {
        self.write(offset, unsafe {
            slice::from_raw_parts(s as *const T as *const u8, mem::size_of_val(s))
        })
    }

    /// Returns a pointer to the start of the buffer.
    ///
    /// # Note
    /// The returned pointer is only valid in the target process.
    #[must_use]
    pub const fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Returns a slice of this buffer.
    #[must_use]
    pub fn slice(&self, bounds: impl RangeBounds<usize>) -> Self {
        let range = utils::range_from_bounds(self.ptr as usize, self.len, &bounds);
        Self {
            process: self.process,
            ptr: range.start as *mut _,
            len: range.len(),
            data: PhantomData,
        }
    }

    /// Flushes the CPU instruction cache for the whole buffer.
    /// This may be necesary if the buffer is used to store dynamically generated code. For details see [`FlushInstructionCache`].
    pub fn flush_instruction_cache(&self) -> Result<(), io::Error> {
        let result = unsafe {
            FlushInstructionCache(self.process.as_raw_handle(), self.as_ptr().cast(), self.len)
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
