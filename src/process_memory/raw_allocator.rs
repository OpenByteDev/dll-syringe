use std::{collections::LinkedList, mem};

use rust_win32error::Win32Error;

use crate::{process_memory::ProcessMemoryBuffer, ProcessRef};

pub trait RawAllocator {
    type Error;
    type Alloc;

    fn alloc(&mut self, size: usize) -> Result<Self::Alloc, Self::Error>;
    fn free(&mut self, allocation: &Self::Alloc);
}

#[derive(Debug)]
pub struct DynamicMultiBufferAllocator<'a> {
    process: ProcessRef<'a>,
    pages: Vec<FixedBufferAllocator<'a>>,
}

impl<'a> DynamicMultiBufferAllocator<'a> {
    pub fn new(process: ProcessRef<'a>) -> Self {
        Self {
            process,
            pages: Vec::new(),
        }
    }

    pub fn process(&self) -> ProcessRef<'a> {
        self.process
    }

    fn alloc_page(&mut self, min_size: usize) -> Result<&mut FixedBufferAllocator<'a>, Win32Error> {
        let os_page_size = ProcessMemoryBuffer::os_page_size();
        let page_size = (min_size / os_page_size + 1) * os_page_size;
        let mem = ProcessMemoryBuffer::allocate(self.process, page_size)?;
        let page = FixedBufferAllocator::new(mem);
        self.pages.push(page);
        Ok(self.pages.last_mut().unwrap())
    }

    #[allow(dead_code)]
    pub fn count_allocated_bytes(&self) -> usize {
        self.pages
            .iter()
            .map(|page| page.count_allocated_bytes())
            .sum()
    }
}

impl RawAllocator for DynamicMultiBufferAllocator<'_> {
    type Error = Win32Error;
    type Alloc = Allocation;

    fn alloc(&mut self, size: usize) -> Result<Self::Alloc, Self::Error> {
        for page in &mut self.pages {
            match page.alloc(size) {
                Ok(allocation) => return Ok(allocation),
                Err(AllocError::Win32(e)) => return Err(e),
                Err(AllocError::OutOfMemory) => continue,
            }
        }

        let page = self.alloc_page(size)?;
        match page.alloc(size) {
            Ok(allocation) => Ok(allocation),
            Err(AllocError::Win32(e)) => Err(e),
            Err(AllocError::OutOfMemory) => unreachable!(),
        }
    }

    fn free(&mut self, allocation: &Self::Alloc) {
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
#[allow(clippy::linkedlist)]
pub struct FixedBufferAllocator<'a> {
    mem: ProcessMemoryBuffer<'a>,
    free_list: LinkedList<MemoryBlock>,
}

impl<'a> FixedBufferAllocator<'a> {
    pub fn new(mem: ProcessMemoryBuffer<'a>) -> Self {
        let free_list = LinkedList::from([MemoryBlock {
            base: mem.as_mut_ptr() as usize,
            len: mem.len(),
        }]);
        Self { mem, free_list }
    }

    #[allow(dead_code)]
    pub fn memory(&self) -> &ProcessMemoryBuffer<'a> {
        &self.mem
    }

    #[allow(dead_code)]
    pub fn process(&self) -> ProcessRef<'a> {
        self.memory().process()
    }

    pub fn count_allocated_bytes(&self) -> usize {
        self.mem.len() - self.count_free_bytes()
    }

    pub fn count_free_bytes(&self) -> usize {
        self.free_list.iter().map(|b| b.len).sum()
    }
}

impl RawAllocator for FixedBufferAllocator<'_> {
    type Error = AllocError;
    type Alloc = Allocation;

    fn alloc(&mut self, mut size: usize) -> Result<Allocation, AllocError> {
        // TODO: smarter alignment calculation
        size = (size + mem::size_of::<u64>() - 1) & !(mem::size_of::<u64>() - 1);

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

    fn free(&mut self, alloc: &Allocation) {
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
                        if merged {
                            // merging with and prev next block
                            let prev_block = cursor.remove_current().unwrap();
                            let next_block = cursor.current().unwrap();
                            next_block.base = prev_block.base;
                            next_block.len += prev_block.len;
                        } else {
                            // only merging with next block
                            next_block.base = alloc.base;
                            next_block.len += alloc.len;
                            merged = true;
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
    use std::mem;

    use crate::process_memory::ProcessMemorySlice;

    use super::*;

    #[test]
    fn single_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiBufferAllocator::new(process);

        let data = [42u8; 100];
        let alloc = allocator.alloc(data.len()).unwrap();
        assert!(alloc.len >= data.len());
        let alloc_mem =
            unsafe { ProcessMemorySlice::from_raw_parts(alloc.as_mut_ptr(), alloc.len, process) };
        alloc_mem.write(0, &data).unwrap();

        assert_eq!(allocator.count_allocated_bytes(), alloc.len);
        assert!(allocator.count_allocated_bytes() >= data.len());
    }

    #[test]
    fn multi_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiBufferAllocator::new(process);

        let data = &[42u8; 100];
        let mut allocated_bytes = 0;
        let mut actual_allocated_bytes = 0;
        for i in 1..data.len() {
            let alloc = allocator.alloc(i).unwrap();
            assert!(alloc.len >= i);
            let alloc_mem = unsafe {
                ProcessMemorySlice::from_raw_parts(alloc.as_mut_ptr(), alloc.len, process)
            };
            alloc_mem.write(0, &data[0..i]).unwrap();

            allocated_bytes += i;
            actual_allocated_bytes += alloc.len;
            assert!(allocator.count_allocated_bytes() >= allocated_bytes);
            assert_eq!(allocator.count_allocated_bytes(), actual_allocated_bytes);
        }
    }

    #[test]
    fn free() {
        let process = ProcessRef::current();
        let memory = ProcessMemoryBuffer::allocate(process, 512).unwrap();
        let mut allocator = FixedBufferAllocator::new(memory);

        assert_eq!(allocator.count_allocated_bytes(), 0);

        let a1 = _free_helper_alloc(&mut allocator, 32);
        let a2 = _free_helper_alloc(&mut allocator, 128);
        let a3 = _free_helper_alloc(&mut allocator, 256);
        _free_helper_free(&mut allocator, a2);
        let a4 = _free_helper_alloc(&mut allocator, 64);
        let a5 = _free_helper_alloc(&mut allocator, 32);
        _free_helper_free(&mut allocator, a3);
        _free_helper_free(&mut allocator, a1);
        _free_helper_free(&mut allocator, a5);
        _free_helper_free(&mut allocator, a4);

        assert_eq!(allocator.count_allocated_bytes(), 0);
    }

    fn _free_helper_alloc(
        allocator: &mut FixedBufferAllocator<'_>,
        allocation_size: usize,
    ) -> Allocation {
        let free_bytes = allocator.count_free_bytes();
        let allocated_bytes = allocator.count_allocated_bytes();

        let alloc = allocator.alloc(allocation_size).unwrap();
        assert!(alloc.len >= allocation_size);

        assert_eq!(
            allocator.count_allocated_bytes(),
            allocated_bytes + alloc.len
        );
        assert_eq!(allocator.count_free_bytes(), free_bytes - alloc.len);

        alloc
    }

    fn _free_helper_free(allocator: &mut FixedBufferAllocator<'_>, allocation: Allocation) {
        let free_bytes = allocator.count_free_bytes();
        let allocated_bytes = allocator.count_allocated_bytes();

        allocator.free(&allocation);

        assert_eq!(
            allocator.count_allocated_bytes(),
            allocated_bytes - allocation.len
        );
        assert_eq!(allocator.count_free_bytes(), free_bytes + allocation.len);
    }

    #[test]
    fn multi_page_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiBufferAllocator::new(process);

        let page_size = ProcessMemoryBuffer::os_page_size();
        let alloc = allocator.alloc(page_size - 1).unwrap();
        assert!(alloc.len >= page_size - 1);
        let alloc = allocator.alloc(page_size - 1).unwrap();
        assert!(alloc.len >= page_size - 1);
    }

    #[test]
    fn correct_align() {
        let process = ProcessRef::current();
        let memory = ProcessMemoryBuffer::allocate_page(process).unwrap();
        let mut allocator = FixedBufferAllocator::new(memory);

        let a = allocator.alloc(mem::size_of::<u8>()).unwrap();
        assert_eq!(a.as_ptr() as usize % mem::align_of::<u8>(), 0);
        let b = allocator.alloc(mem::size_of::<u16>()).unwrap();
        assert_eq!(b.as_ptr() as usize % mem::align_of::<u16>(), 0);
        let c = allocator.alloc(mem::size_of::<u32>()).unwrap();
        assert_eq!(c.as_ptr() as usize % mem::align_of::<u32>(), 0);
        let d = allocator.alloc(mem::size_of::<u64>()).unwrap();
        assert_eq!(d.as_ptr() as usize % mem::align_of::<u64>(), 0);
        let e = allocator.alloc(mem::size_of::<AlignTestStruct>()).unwrap();
        assert_eq!(e.as_ptr() as usize % mem::align_of::<AlignTestStruct>(), 0);
    }

    #[test]
    fn large_alloc() {
        let process = ProcessRef::current();
        let mut allocator = DynamicMultiBufferAllocator::new(process);

        let page_size = ProcessMemoryBuffer::os_page_size();
        let alloc = allocator.alloc(page_size + 1).unwrap();
        assert!(alloc.len > page_size);
    }
}

#[cfg(test)]
struct AlignTestStruct {
    _a: u8,
    _b: u16,
    _c: u32,
    _d: u64,
}
