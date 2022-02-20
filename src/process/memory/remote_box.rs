use std::{cell::RefCell, io, marker::PhantomData, mem, ptr::NonNull, rc::Rc};

use crate::process::{
    memory::{Allocation, DynamicMultiBufferAllocator, ProcessMemorySlice, RawAllocator},
    BorrowedProcess, OwnedProcess, Process,
};

#[derive(Debug, Clone)]
pub struct RemoteBoxAllocator(pub(crate) Rc<RemoteBoxAllocatorInner>);

#[derive(Debug)]
pub(crate) struct RemoteBoxAllocatorInner {
    pub(crate) process: OwnedProcess,
    pub(crate) allocator: RefCell<DynamicMultiBufferAllocator<'static>>,
}

impl RemoteBoxAllocator {
    pub fn new(process: OwnedProcess) -> Self {
        Self(Rc::new(RemoteBoxAllocatorInner {
            allocator: RefCell::new(DynamicMultiBufferAllocator::new(unsafe {
                process.borrowed_static()
            })),
            process,
        }))
    }

    pub fn process(&self) -> BorrowedProcess<'_> {
        self.0.process.borrowed()
    }

    pub unsafe fn alloc_raw<T: ?Sized>(&self, size: usize) -> Result<RemoteBox<T>, io::Error> {
        let allocation = self.0.allocator.borrow_mut().alloc(size)?;
        Ok(RemoteBox::new(self.clone(), allocation))
    }
    pub fn alloc_uninit<T: Sized>(&self) -> Result<RemoteBox<T>, io::Error> {
        unsafe { self.alloc_raw(mem::size_of::<T>()) }
    }
    pub fn alloc_uninit_for<T: ?Sized>(&self, value: &T) -> Result<RemoteBox<T>, io::Error> {
        unsafe { self.alloc_raw(mem::size_of_val(value)) }
    }
    pub fn alloc_and_copy<T: ?Sized>(&self, value: &T) -> Result<RemoteBox<T>, io::Error> {
        let b = self.alloc_uninit_for(value)?;
        b.write(value)?;
        Ok(b)
    }

    fn free(&self, allocation: &Allocation) {
        self.0.allocator.borrow_mut().free(allocation);
    }
}

#[derive(Debug)]
pub struct RemoteBox<T: ?Sized> {
    allocation: Allocation,
    allocator: RemoteBoxAllocator,
    phantom: PhantomData<T>,
}

impl<T: ?Sized> RemoteBox<T> {
    const fn new(allocator: RemoteBoxAllocator, allocation: Allocation) -> Self {
        Self {
            allocation,
            allocator,
            phantom: PhantomData,
        }
    }

    pub fn process(&self) -> BorrowedProcess<'_> {
        self.allocator.process()
    }

    pub fn memory(&self) -> ProcessMemorySlice<'_> {
        unsafe {
            ProcessMemorySlice::from_raw_parts(
                self.allocation.as_raw_ptr(),
                self.allocation.len,
                self.process(),
            )
        }
    }

    pub fn write(&self, value: &T) -> Result<(), io::Error> {
        self.memory().write_struct(0, value)
    }

    pub const fn as_raw_ptr(&self) -> *mut u8 {
        self.allocation.as_raw_ptr()
    }
}

impl<'a, T: Sized> RemoteBox<T> {
    pub fn read(&self) -> Result<T, io::Error> {
        unsafe { self.memory().read_struct::<T>(0) }
    }

    #[allow(dead_code)]
    pub const fn as_ptr(&self) -> NonNull<T> {
        self.allocation.as_ptr().cast()
    }
}

impl<T: ?Sized> Drop for RemoteBox<T> {
    fn drop(&mut self) {
        self.allocator.free(&self.allocation);
    }
}
