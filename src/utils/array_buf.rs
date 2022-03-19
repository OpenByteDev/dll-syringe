use std::{
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut},
    ptr,
};

#[derive(Debug)]
pub(crate) struct ArrayBuf<T, const SIZE: usize> {
    data: [MaybeUninit<T>; SIZE],
    len: usize,
}

impl<T, const SIZE: usize> ArrayBuf<T, SIZE> {
    pub fn new_uninit() -> Self {
        Self {
            data: MaybeUninit::uninit_array(),
            len: 0,
        }
    }

    pub fn from_array(mut array: [T; SIZE]) -> Self {
        let data = unsafe { ptr::read(&mut array as *mut _ as *mut [MaybeUninit<T>; SIZE]) };
        Self { data, len: SIZE }
    }

    pub fn from_partial_init_array(array: [MaybeUninit<T>; SIZE], len: usize) -> Self {
        Self { data: array, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        SIZE
    }

    pub unsafe fn set_len(&mut self, new_len: usize) {
        assert!(new_len <= SIZE, "ArrayBuf::set_len: len > SIZE");
        self.len = new_len;
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { MaybeUninit::slice_assume_init_ref(&self.data[..self.len]) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { MaybeUninit::slice_assume_init_mut(&mut self.data[..self.len]) }
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        &mut self.data[self.len..]
    }

    pub fn clear(&mut self) {
        for e in &mut self.data[0..self.len] {
            unsafe { e.assume_init_drop() };
        }
        self.len = 0;
    }

    pub fn to_vec(&self) -> Vec<T>
    where
        T: Copy,
    {
        let mut vec = Vec::with_capacity(self.len());
        vec.extend_from_slice(self.as_slice());
        vec
    }
}

impl<T, const SIZE: usize> AsRef<[T]> for ArrayBuf<T, SIZE> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}
impl<T, const SIZE: usize> AsMut<[T]> for ArrayBuf<T, SIZE> {
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T, const SIZE: usize> Deref for ArrayBuf<T, SIZE> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_ref()
    }
}

impl<T, const SIZE: usize> DerefMut for ArrayBuf<T, SIZE> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut()
    }
}

impl<T, const SIZE: usize> From<[T; SIZE]> for ArrayBuf<T, SIZE> {
    fn from(array: [T; SIZE]) -> Self {
        Self::from_array(array)
    }
}

impl<T, const SIZE: usize> Drop for ArrayBuf<T, SIZE> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) struct ArrayBufIter<T, const SIZE: usize> {
    buf: ManuallyDrop<ArrayBuf<T, SIZE>>,
    offset: usize,
}

impl<T, const SIZE: usize> IntoIterator for ArrayBuf<T, SIZE> {
    type Item = T;
    type IntoIter = ArrayBufIter<T, SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        ArrayBufIter {
            buf: ManuallyDrop::new(self),
            offset: 0,
        }
    }
}

impl<T, const SIZE: usize> Iterator for ArrayBufIter<T, SIZE> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len() == 0 {
            return None;
        }

        let item = unsafe { MaybeUninit::assume_init_read(&self.buf.data[self.offset]) };
        self.offset += 1;
        Some(item)
    }
}

impl<T, const SIZE: usize> DoubleEndedIterator for ArrayBufIter<T, SIZE> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.len() == 0 {
            return None;
        }

        let item = unsafe { MaybeUninit::assume_init_read(&self.buf.data[self.buf.len - 1]) };
        self.buf.len -= 1;
        Some(item)
    }
}

impl<T, const SIZE: usize> ExactSizeIterator for ArrayBufIter<T, SIZE> {
    fn len(&self) -> usize {
        self.buf.len - self.offset
    }
}

impl<T, const SIZE: usize> Drop for ArrayBufIter<T, SIZE> {
    fn drop(&mut self) {
        let len = self.buf.len();
        for e in &mut self.buf.data[self.offset..len] {
            unsafe { e.assume_init_drop() };
        }
        self.buf.len = 0;
    }
}
