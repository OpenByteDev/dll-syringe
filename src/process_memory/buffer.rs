use std::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::{Bound, Deref, DerefMut, Range, RangeBounds},
    ptr, slice,
};

use rust_win32error::Win32Error;
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

use crate::ProcessRef;

/// A owned memory buffer in the memory space of a (remote) process.
#[derive(Debug)]
#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "process_memory")))]
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
    pub fn allocate(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_code(process, len)
    }
    /// Allocates a new buffer with the size of a memory page in the given process.
    pub fn allocate_page(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate_code(process, Self::os_page_size())
    }
    /// Allocates a new data buffer of the given length in the given process.
    pub fn allocate_data(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_with_options(process, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    }
    /// Allocates a new data buffer with the size of a memory page in the given process.
    pub fn allocate_data_page(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate_data(process, Self::os_page_size())
    }
    /// Allocates a new codea buffer of the given length in the given process.
    pub fn allocate_code(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_with_options(
            process,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    }
    /// Allocates a new code buffer with the size of a memory page in the given process.
    pub fn allocate_code_page(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate_code(process, Self::os_page_size())
    }
    fn allocate_with_options(
        process: ProcessRef<'a>,
        len: usize,
        allocation_type: DWORD,
        protection: DWORD,
    ) -> Result<Self, Win32Error> {
        let ptr = if process.is_current() {
            unsafe { VirtualAlloc(ptr::null_mut(), len, allocation_type, protection) }
        } else {
            unsafe {
                VirtualAllocEx(
                    process.handle(),
                    ptr::null_mut(),
                    len,
                    allocation_type,
                    protection,
                )
            }
        };

        return if ptr.is_null() {
            Err(Win32Error::new())
        } else {
            Ok(unsafe { Self::from_raw_parts(ptr.cast(), len, process) })
        };
    }

    /// Allocates a new buffer with enough space to store a value of type `T` in the given process.
    pub fn allocate_for<T>(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate_data(process, mem::size_of::<T>())
    }
    /// Allocates a new buffer with enough space to store a value of type `T` in the given process.
    pub fn allocate_and_write<T: ?Sized>(
        process: ProcessRef<'a>,
        s: &T,
    ) -> Result<Self, Win32Error> {
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
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize, process: ProcessRef<'a>) -> Self {
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
    pub fn free(mut self) -> Result<(), Win32Error> {
        unsafe { self._free() }
    }
    unsafe fn _free(&mut self) -> Result<(), Win32Error> {
        let result = if self.is_local() {
            unsafe { VirtualFree(self.as_mut_ptr().cast(), self.len(), MEM_RELEASE) }
        } else {
            unsafe {
                VirtualFreeEx(
                    self.process.handle(),
                    self.as_mut_ptr().cast(),
                    self.len(),
                    MEM_RELEASE,
                )
            }
        };

        if result == 0 {
            Ok(())
        } else {
            Err(Win32Error::new())
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

/// A unowned slice of a memory buffer in the memory space of a (remote) process.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemorySlice<'a> {
    process: ProcessRef<'a>,
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
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize, process: ProcessRef<'a>) -> Self {
        Self {
            ptr,
            len,
            process,
            data: PhantomData,
        }
    }

    /// Returns whether the memory is allocated in the local process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }
    /// Returns whether the memory is allocated in a remote process.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }
    /// Returns the process the buffer is allocated in.
    #[must_use]
    pub fn process(&self) -> ProcessRef<'a> {
        self.process
    }
    /// Returns the length of the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }
    /// Returns whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the contents of this buffer at the given offset to the given local buffer.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the given buffer length exceeds this buffer's length.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), Win32Error> {
        assert!(offset + buf.len() <= self.len, "read out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
            }
            return Ok(());
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

    /// Reads a value of type `T` from this buffer at the given offset.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the size of the value exceeds this buffer's length.
    ///
    /// # Safety
    /// The caller must ensure that the designated region of memory contains a valid instance of type `T` at the given offset.
    pub unsafe fn read_struct<T>(&self, offset: usize) -> Result<T, Win32Error> {
        let mut uninit_value = MaybeUninit::<T>::uninit();
        self.read(offset, unsafe {
            slice::from_raw_parts_mut(uninit_value.as_mut_ptr().cast(), mem::size_of::<T>())
        })?;
        Ok(unsafe { uninit_value.assume_init() })
    }

    /// Copies the contents of this buffer at the given offset to the given local buffer.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the size of the local buffer exceeds this buffer's length.
    pub fn write(&self, offset: usize, buf: &[u8]) -> Result<(), Win32Error> {
        assert!(offset + buf.len() <= self.len, "write out of bounds");

        if self.is_local() {
            unsafe {
                ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.add(offset), buf.len());
            }
            return Ok(());
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

    /// Writes a value of type `T` to this buffer at the given offset.
    ///
    /// # Panics
    /// This function will panic if the given offset plus the given buffer length exceeds this buffer's length.
    pub fn write_struct<T: ?Sized>(&self, offset: usize, s: &T) -> Result<(), Win32Error> {
        self.write(offset, unsafe {
            slice::from_raw_parts(s as *const T as *const u8, mem::size_of_val(s))
        })
    }

    /// Returns a pointer to the start of the buffer.
    ///
    /// # Note
    /// The returned pointer is only valid in the target process.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    /// Returns a mutable pointer to the start of the buffer.
    ///
    /// # Note
    /// The returned pointer is only valid in the target process.
    #[must_use]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Returns a slice of the buffer.
    #[must_use]
    pub fn slice(&self, bounds: impl RangeBounds<usize>) -> Self {
        let range = range_from_bounds(self.ptr as usize, self.len, &bounds);
        Self {
            process: self.process,
            ptr: range.start as *mut _,
            len: range.len(),
            data: PhantomData,
        }
    }

    /// Flushes the CPU instruction cache for the whole buffer.
    /// This may be necesary if the buffer is used to store dynamically generated code. For details see [`FlushInstructionCache`].
    pub fn flush_instruction_cache(&self) -> Result<(), Win32Error> {
        self.flush_instruction_cache_of_range(..)
    }

    /// Flushes the CPU instruction cache for the given buffer range.
    /// This may be necesary if the buffer is used to store dynamically generated code. For details see [`FlushInstructionCache`].
    pub fn flush_instruction_cache_of_range(
        &self,
        bounds: impl RangeBounds<usize>,
    ) -> Result<(), Win32Error> {
        let range = range_from_bounds(0, self.len(), &bounds);
        let base_ptr = unsafe { self.ptr.add(range.start) };
        let range_len = range.len();

        let res =
            unsafe { FlushInstructionCache(self.process.handle(), base_ptr.cast(), range_len) };
        if res == 0 {
            Err(Win32Error::new())
        } else {
            Ok(())
        }
    }
}

fn range_from_bounds(offset: usize, len: usize, range: &impl RangeBounds<usize>) -> Range<usize> {
    let rel_start = match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(start) => *start,
        Bound::Excluded(start) => start + 1,
    };
    let rel_end = match range.end_bound() {
        Bound::Unbounded => len,
        Bound::Included(end) => *end,
        Bound::Excluded(end) => end - 1,
    };

    assert!(rel_start <= len, "range start out of bounds");
    assert!(rel_end <= len, "range end out of bounds");
    assert!(rel_end >= rel_start, "range end before start");

    let start = offset + rel_start;
    let end = offset + rel_end;
    Range { start, end }
}
