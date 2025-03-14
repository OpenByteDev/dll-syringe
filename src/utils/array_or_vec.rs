use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    vec,
};

use super::{ArrayBuf, ArrayBufIter};

#[derive(Debug)]
pub(crate) enum ArrayOrVecBuf<T, const SIZE: usize> {
    Array(ArrayBuf<T, SIZE>),
    Vec(Vec<T>),
}

impl<T, const SIZE: usize> Default for ArrayOrVecBuf<T, SIZE> {
    fn default() -> Self {
        Self::Vec(Vec::new())
    }
}

impl<T, const SIZE: usize> ArrayOrVecBuf<T, SIZE> {
    pub fn with_capacity(capacity: usize) -> Self {
        if capacity <= SIZE {
            Self::new_uninit_array()
        } else {
            Self::Vec(Vec::with_capacity(capacity))
        }
    }

    pub fn new_uninit_array() -> Self {
        Self::from_partial_init_array([const { MaybeUninit::uninit() }; SIZE], 0)
    }

    pub fn from_array(array: [T; SIZE]) -> Self {
        Self::Array(ArrayBuf::from_array(array))
    }

    pub fn from_partial_init_array(array: [MaybeUninit<T>; SIZE], len: usize) -> Self {
        Self::Array(ArrayBuf::from_partial_init_array(array, len))
    }

    pub fn from_vec(vec: Vec<T>) -> Self {
        Self::Vec(vec)
    }

    pub fn len(&self) -> usize {
        match self {
            ArrayOrVecBuf::Array(array) => array.len(),
            ArrayOrVecBuf::Vec(vec) => vec.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        match self {
            ArrayOrVecBuf::Array(array) => array.capacity(),
            ArrayOrVecBuf::Vec(vec) => vec.capacity(),
        }
    }

    pub unsafe fn set_len(&mut self, new_len: usize) {
        match self {
            ArrayOrVecBuf::Array(array) => unsafe { array.set_len(new_len) },
            ArrayOrVecBuf::Vec(vec) => unsafe { vec.set_len(new_len) },
        }
    }

    pub fn clear(&mut self) {
        match self {
            ArrayOrVecBuf::Array(array) => array.clear(),
            ArrayOrVecBuf::Vec(vec) => vec.clear(),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            ArrayOrVecBuf::Array(array) => array.as_slice(),
            ArrayOrVecBuf::Vec(vec) => vec.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            ArrayOrVecBuf::Array(array) => array.as_mut_slice(),
            ArrayOrVecBuf::Vec(vec) => vec.as_mut_slice(),
        }
    }

    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        match self {
            ArrayOrVecBuf::Array(array) => array.spare_capacity_mut(),
            ArrayOrVecBuf::Vec(vec) => vec.spare_capacity_mut(),
        }
    }

    pub fn into_vec(self) -> Vec<T>
    where
        T: Copy,
    {
        match self {
            Self::Array(array) => array.to_vec(),
            Self::Vec(vec) => vec,
        }
    }

    pub fn ensure_capacity(&mut self, capacity: usize)
    where
        T: Copy,
    {
        match self {
            ArrayOrVecBuf::Array { .. } => {
                if SIZE >= capacity {
                    return;
                }

                let mut vec = Vec::with_capacity(capacity);
                vec.copy_from_slice(self.as_slice());
                *self = Self::Vec(vec);
            }
            ArrayOrVecBuf::Vec(vec) => {
                if vec.capacity() >= capacity {
                    return;
                }

                vec.reserve(capacity - vec.capacity());
            }
        }
    }
}

impl<const SIZE: usize> ArrayOrVecBuf<u8, SIZE> {
    pub fn spare_writer(&mut self) -> impl std::io::Write + '_ {
        let spare = self.spare_capacity_mut();
        unsafe { spare.assume_init_mut() }
    }
}

impl<T, const SIZE: usize> AsRef<[T]> for ArrayOrVecBuf<T, SIZE> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}
impl<T, const SIZE: usize> AsMut<[T]> for ArrayOrVecBuf<T, SIZE> {
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T, const SIZE: usize> Deref for ArrayOrVecBuf<T, SIZE> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_ref()
    }
}

impl<T, const SIZE: usize> DerefMut for ArrayOrVecBuf<T, SIZE> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut()
    }
}

impl<T, const SIZE: usize> From<[T; SIZE]> for ArrayOrVecBuf<T, SIZE> {
    fn from(array: [T; SIZE]) -> Self {
        Self::from_array(array)
    }
}

impl<T, const SIZE: usize> From<Vec<T>> for ArrayOrVecBuf<T, SIZE> {
    fn from(vec: Vec<T>) -> Self {
        Self::from_vec(vec)
    }
}

pub(crate) enum ArrayOrVecBufIter<T, const SIZE: usize> {
    Array(ArrayBufIter<T, SIZE>),
    Vec(vec::IntoIter<T>),
}

impl<T, const SIZE: usize> IntoIterator for ArrayOrVecBuf<T, SIZE> {
    type Item = T;
    type IntoIter = ArrayOrVecBufIter<T, SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Array(array) => ArrayOrVecBufIter::Array(array.into_iter()),
            Self::Vec(vec) => ArrayOrVecBufIter::Vec(vec.into_iter()),
        }
    }
}

impl<T, const SIZE: usize> Iterator for ArrayOrVecBufIter<T, SIZE> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ArrayOrVecBufIter::Array(array) => array.next(),
            ArrayOrVecBufIter::Vec(iter) => iter.next(),
        }
    }
}

impl<T, const SIZE: usize> DoubleEndedIterator for ArrayOrVecBufIter<T, SIZE> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            ArrayOrVecBufIter::Array(iter) => iter.next_back(),
            ArrayOrVecBufIter::Vec(iter) => iter.next_back(),
        }
    }
}

impl<T, const SIZE: usize> ExactSizeIterator for ArrayOrVecBufIter<T, SIZE> {
    fn len(&self) -> usize {
        match self {
            ArrayOrVecBufIter::Array(iter) => iter.len(),
            ArrayOrVecBufIter::Vec(iter) => iter.len(),
        }
    }
}
