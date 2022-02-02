use std::{
    collections::LinkedList,
    hash::{Hash, Hasher},
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::{Bound, Range, RangeBounds},
    ptr, slice,
};

use rust_win32error::Win32Error;
use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::*, processthreadsapi::FlushInstructionCache, sysinfoapi::GetSystemInfo, winnt::*,
    },
};

use crate::ProcessRef;

#[derive(Debug)]
pub struct SharedMemory<'a> {
    ptr: *mut u8,
    process: ProcessRef<'a>,
    len: usize,
    is_owner: bool,
    data: PhantomData<&'a [u8]>,
}

impl PartialEq for SharedMemory<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr && self.process == other.process
    }
}

impl Eq for SharedMemory<'_> {}

impl Hash for SharedMemory<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ptr.hash(state);
        self.process.hash(state);
    }
}

impl<'a> SharedMemory<'a> {
    pub fn allocate(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
        Self::allocate_code(process, len)
    }
    pub fn allocate_data(process: ProcessRef<'a>, len: usize) -> Result<Self, Win32Error> {
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
            Ok(unsafe { Self::from_parts(ptr.cast(), process, len, true) })
        };
    }
    pub fn allocate_uninit_struct<T>(process: ProcessRef<'a>) -> Result<Self, Win32Error> {
        Self::allocate_data(process, mem::size_of::<T>())
    }
    pub fn allocate_struct<T: ?Sized>(process: ProcessRef<'a>, s: &T) -> Result<Self, Win32Error> {
        let buf = Self::allocate_data(process, mem::size_of_val(s))?;
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
            data: PhantomData,
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

    pub fn flush_instruction_cache(&self) -> Result<(), Win32Error> {
        self.flush_instruction_cache_of_range(..)
    }

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

    pub fn os_page_size() -> usize {
        let mut system_info = MaybeUninit::uninit();
        unsafe { GetSystemInfo(system_info.as_mut_ptr()) };
        unsafe { system_info.assume_init() }.dwPageSize as usize
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
        assert!(self.is_owner);

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

        self.is_owner = false;

        if result != 0 {
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

    if rel_start > len {
        panic!("range start out of bounds");
    }
    if rel_end > len {
        panic!("range end out of bounds");
    }
    if rel_end < rel_start {
        panic!("range end before start");
    }

    let start = offset + rel_start;
    let end = offset + rel_end;
    Range { start, end }
}

impl Drop for SharedMemory<'_> {
    fn drop(&mut self) {
        if self.is_owner() {
            let _ = unsafe { self._free() };
        }
    }
}

pub trait Allocator {
    type Error;
    type Alloc;

    fn alloc(&mut self, size: usize) -> Result<Self::Alloc, Self::Error>;
    fn free(&mut self, allocation: Self::Alloc);
}

#[derive(Debug)]
pub struct DynamicMultiPageAllocator<'a> {
    process: ProcessRef<'a>,
    pages: Vec<FixedPageAllocator<'a>>,
}

impl<'a> DynamicMultiPageAllocator<'a> {
    pub fn new(process: ProcessRef<'a>) -> Self {
        Self {
            process,
            pages: Vec::new(),
        }
    }

    fn alloc_page(&mut self) -> Result<&mut FixedPageAllocator<'a>, Win32Error> {
        let mem = SharedMemory::allocate(self.process, SharedMemory::os_page_size())?;
        let page = FixedPageAllocator::new(mem);
        self.pages.push(page);
        Ok(self.pages.last_mut().unwrap())
    }

    pub fn count_allocated_bytes(&self) -> usize {
        self.pages
            .iter()
            .map(|page| page.count_allocated_bytes())
            .sum()
    }
}

impl Allocator for DynamicMultiPageAllocator<'_> {
    type Error = AllocError;
    type Alloc = Allocation;

    fn alloc(&mut self, size: usize) -> Result<Self::Alloc, Self::Error> {
        for page in &mut self.pages {
            let alloc = page.alloc(size);
            if matches!(alloc, Ok(_) | Err(AllocError::Win32(_))) {
                return alloc;
            }
        }

        // TODO: handle large allocations (> page size)
        let page = self.alloc_page()?;
        page.alloc(size)
    }

    fn free(&mut self, allocation: Self::Alloc) {
        for page in &mut self.pages {
            let page_start = page.mem.as_ptr() as usize;
            let page_end = page_start + page.mem.len();
            if allocation.base >= page_start && allocation.base < page_end {
                page.free(allocation);
                return;
            }
        }
        panic!("allocation not found");
    }
}

#[derive(Debug)]
pub struct FixedPageAllocator<'a> {
    mem: SharedMemory<'a>,
    free_list: LinkedList<MemoryBlock>,
}

impl<'a> FixedPageAllocator<'a> {
    pub fn new(mem: SharedMemory<'a>) -> Self {
        let free_list = LinkedList::from([MemoryBlock {
            base: mem.as_mut_ptr() as usize,
            len: mem.len(),
        }]);
        Self { mem, free_list }
    }

    pub fn count_allocated_bytes(&self) -> usize {
        self.mem.len() - self.count_free_bytes()
    }

    pub fn count_free_bytes(&self) -> usize {
        self.free_list.iter().map(|b| b.len).sum()
    }
}

impl Allocator for FixedPageAllocator<'_> {
    type Error = AllocError;
    type Alloc = Allocation;

    fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        let mut cursor = self.free_list.cursor_front_mut();
        while let Some(block) = cursor.current() {
            if block.len >= size {
                let alloc = Allocation {
                    base: block.base,
                    len: size,
                };
                block.base += size;
                block.len -= size;

                if block.len == 0 {
                    cursor.remove_current();
                }

                return Ok(alloc);
            }
            cursor.move_next();
        }
        Err(AllocError::OutOfMemory)
    }

    fn free(&mut self, alloc: Allocation) {
        let mut cursor = self.free_list.cursor_front_mut();
        while let Some(block) = cursor.current() {
            if alloc.base > block.base {
                let prev_block = block;
                let mut merged = false;

                if alloc.base == prev_block.base + prev_block.len {
                    // Alloc is directly after a free block -> merge
                    prev_block.len += alloc.len;
                    merged = true;
                }

                if let Some(next_block) = cursor.peek_next() {
                    if alloc.base + alloc.len == next_block.base {
                        // Alloc is directly before a free block -> merge
                        if !merged {
                            // only merging with next block
                            next_block.base = alloc.base;
                            next_block.len += alloc.len;
                            merged = true;
                        } else {
                            // merging with and prev next block
                            let prev_block = cursor.remove_current().unwrap();
                            let next_block = cursor.current().unwrap();
                            next_block.base = prev_block.base;
                            next_block.len += prev_block.len;
                        }
                    }
                }

                // Alloc is not directly before or after a free block -> insert
                if !merged {
                    cursor.insert_after(MemoryBlock {
                        base: alloc.base,
                        len: alloc.len,
                    });
                }

                return;
            }

            cursor.move_next();
        }

        // no free block found -> insert
        cursor.insert_after(MemoryBlock {
            base: alloc.base,
            len: alloc.len,
        });
    }
}

#[derive(Debug)]
pub struct MemoryBlock {
    base: usize,
    len: usize,
}

#[derive(Debug)]
pub struct Allocation {
    pub base: usize,
    pub len: usize,
}

impl Allocation {
    pub fn as_ptr(&self) -> *const u8 {
        self.base as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.base as *mut u8
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AllocError {
    #[error("out of memory")]
    OutOfMemory,
    #[error("windows api error: {}", _0)]
    Win32(#[from] Win32Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiPageAllocator::new(process);

        let data = [42u8; 100];
        let alloc = allocator.alloc(data.len()).unwrap();
        assert_eq!(alloc.len, data.len());
        let alloc_mem =
            unsafe { SharedMemory::from_parts(alloc.as_mut_ptr(), process, alloc.len, false) };
        alloc_mem.write(0, &data).unwrap();

        assert_eq!(allocator.count_allocated_bytes(), data.len());
    }

    #[test]
    fn multi_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiPageAllocator::new(process);

        let data = &[42u8; 100];
        let mut allocated_bytes = 0;
        for i in 1..data.len() {
            let alloc = allocator.alloc(i).unwrap();
            assert_eq!(alloc.len, i);
            let alloc_mem =
                unsafe { SharedMemory::from_parts(alloc.as_mut_ptr(), process, alloc.len, false) };
            alloc_mem.write(0, &data[0..i]).unwrap();

            allocated_bytes += i;
            assert_eq!(allocator.count_allocated_bytes(), allocated_bytes);
        }
    }

    #[test]
    fn free() {
        let process = ProcessRef::current();
        let memory = SharedMemory::allocate(process, 400).unwrap();
        let mut allocator = FixedPageAllocator::new(memory);

        assert_eq!(allocator.count_allocated_bytes(), 0);

        let a1 = _free_helper_alloc(&mut allocator, 42);
        let a2 = _free_helper_alloc(&mut allocator, 132);
        let a3 = _free_helper_alloc(&mut allocator, 226);
        _free_helper_free(&mut allocator, a2);
        let a4 = _free_helper_alloc(&mut allocator, 43);
        let a5 = _free_helper_alloc(&mut allocator, 42);
        _free_helper_free(&mut allocator, a3);
        _free_helper_free(&mut allocator, a1);
        _free_helper_free(&mut allocator, a5);
        _free_helper_free(&mut allocator, a4);

        assert_eq!(allocator.count_allocated_bytes(), 0);
    }

    fn _free_helper_alloc(
        allocator: &mut FixedPageAllocator,
        allocation_size: usize,
    ) -> Allocation {
        let free_bytes = allocator.count_free_bytes();
        let allocated_bytes = allocator.count_allocated_bytes();

        let alloc = allocator.alloc(allocation_size).unwrap();
        assert_eq!(alloc.len, allocation_size);

        assert_eq!(
            allocator.count_allocated_bytes(),
            allocated_bytes + allocation_size
        );
        assert_eq!(allocator.count_free_bytes(), free_bytes - allocation_size);

        alloc
    }

    fn _free_helper_free(allocator: &mut FixedPageAllocator, allocation: Allocation) {
        let allocation_size = allocation.len;
        let free_bytes = allocator.count_free_bytes();
        let allocated_bytes = allocator.count_allocated_bytes();

        allocator.free(allocation);

        assert_eq!(
            allocator.count_allocated_bytes(),
            allocated_bytes - allocation_size
        );
        assert_eq!(allocator.count_free_bytes(), free_bytes + allocation_size);
    }

    #[test]
    fn multi_page_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiPageAllocator::new(process);

        let page_size = SharedMemory::os_page_size();
        let alloc = allocator.alloc(page_size - 1).unwrap();
        assert_eq!(alloc.len, page_size - 1);
        let alloc = allocator.alloc(page_size - 1).unwrap();
        assert_eq!(alloc.len, page_size - 1);
    }

    // TODO: #[test]
    fn large_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiPageAllocator::new(process);

        let page_size = SharedMemory::os_page_size();
        let alloc = allocator.alloc(page_size + 1).unwrap();
        assert_eq!(alloc.len, page_size + 1);
    }
}
