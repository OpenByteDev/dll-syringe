use std::{
    mem::MaybeUninit,
    ops::{Deref, Range, RangeBounds},
};

use crate::utils;

#[derive(Debug)]
pub(crate) enum ArrayOrVec<T, const SIZE: usize> {
    Array([T; SIZE]),
    Vec(Vec<T>),
}

impl<T, const SIZE: usize> AsRef<[T]> for ArrayOrVec<T, SIZE> {
    fn as_ref(&self) -> &[T] {
        match self {
            ArrayOrVec::Array(ref array) => array.as_ref(),
            ArrayOrVec::Vec(ref vec) => vec.as_ref(),
        }
    }
}

impl<T, const SIZE: usize> Deref for ArrayOrVec<T, SIZE> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_ref()
    }
}

impl<T, const SIZE: usize> Default for ArrayOrVec<T, SIZE> {
    fn default() -> Self {
        Self::Vec(Vec::new())
    }
}

impl<T, const SIZE: usize> From<[T; SIZE]> for ArrayOrVec<T, SIZE> {
    fn from(array: [T; SIZE]) -> Self {
        Self::Array(array)
    }
}

impl<T, const SIZE: usize> From<Vec<T>> for ArrayOrVec<T, SIZE> {
    fn from(vec: Vec<T>) -> Self {
        Self::Vec(vec)
    }
}

impl<'a, T, const SIZE: usize> From<&'a ArrayOrVec<T, SIZE>> for &'a [T] {
    fn from(array_or_vec: &'a ArrayOrVec<T, SIZE>) -> Self {
        array_or_vec.as_ref()
    }
}

pub(crate) enum ArrayOrVecIter<T, const SIZE: usize> {
    Array(<[T; SIZE] as IntoIterator>::IntoIter),
    Vec(<Vec<T> as IntoIterator>::IntoIter),
}

impl<T, const SIZE: usize> IntoIterator for ArrayOrVec<T, SIZE> {
    type Item = T;
    type IntoIter = ArrayOrVecIter<T, SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            ArrayOrVec::Array(array) => ArrayOrVecIter::Array(array.into_iter()),
            ArrayOrVec::Vec(vec) => ArrayOrVecIter::Vec(vec.into_iter()),
        }
    }
}

impl<T, const SIZE: usize> Iterator for ArrayOrVecIter<T, SIZE> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ArrayOrVecIter::Array(iter) => iter.next(),
            ArrayOrVecIter::Vec(iter) => iter.next(),
        }
    }
}

impl<T, const SIZE: usize> DoubleEndedIterator for ArrayOrVecIter<T, SIZE> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            ArrayOrVecIter::Array(iter) => iter.next_back(),
            ArrayOrVecIter::Vec(iter) => iter.next_back(),
        }
    }
}

impl<T, const SIZE: usize> ExactSizeIterator for ArrayOrVecIter<T, SIZE> {
    fn len(&self) -> usize {
        match self {
            ArrayOrVecIter::Array(iter) => iter.len(),
            ArrayOrVecIter::Vec(iter) => iter.len(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ArrayOrVecSlice<T, const SIZE: usize> {
    data: ArrayOrVec<T, SIZE>,
    range: Range<usize>,
}

impl<T, const SIZE: usize> ArrayOrVecSlice<T, SIZE> {
    pub fn from_array(array: [T; SIZE], range: impl RangeBounds<usize>) -> Self {
        Self {
            range: utils::range_from_bounds(0, array.len(), &range),
            data: ArrayOrVec::Array(array),
        }
    }

    #[allow(dead_code)]
    pub unsafe fn from_array_assume_init(
        array: [MaybeUninit<T>; SIZE],
        range: impl RangeBounds<usize>,
    ) -> Self {
        Self::from_array(unsafe { MaybeUninit::array_assume_init(array) }, range)
    }

    pub fn from_vec(vec: Vec<T>, range: impl RangeBounds<usize>) -> Self {
        Self {
            range: utils::range_from_bounds(0, vec.len(), &range),
            data: ArrayOrVec::Vec(vec),
        }
    }

    pub unsafe fn from_vec_assume_init(
        vec: Vec<MaybeUninit<T>>,
        range: impl RangeBounds<usize>,
    ) -> Self {
        let (ptr, length, capacity) = vec.into_raw_parts();
        Self::from_vec(
            unsafe { Vec::from_raw_parts(ptr.cast(), length, capacity) },
            range,
        )
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[T] {
        match self.data {
            ArrayOrVec::Array(ref array) => &array[self.range.start..self.range.end],
            ArrayOrVec::Vec(ref vec) => &vec[self.range.start..self.range.end],
        }
    }
}

impl<T, const SIZE: usize> AsRef<[T]> for ArrayOrVecSlice<T, SIZE> {
    fn as_ref(&self) -> &[T] {
        &self.data.as_ref()[self.range.start..self.range.end]
    }
}

impl<T, const SIZE: usize> Deref for ArrayOrVecSlice<T, SIZE> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_ref()
    }
}

impl<T, const SIZE: usize> From<ArrayOrVec<T, SIZE>> for ArrayOrVecSlice<T, SIZE> {
    fn from(array_or_vec: ArrayOrVec<T, SIZE>) -> Self {
        Self {
            range: Range {
                start: 0,
                end: array_or_vec.len(),
            },
            data: array_or_vec,
        }
    }
}

pub(crate) struct ArrayOrVecSliceIter<T, const SIZE: usize>(
    std::iter::Skip<std::iter::Take<ArrayOrVecIter<T, SIZE>>>,
);

impl<T, const SIZE: usize> IntoIterator for ArrayOrVecSlice<T, SIZE> {
    type Item = T;
    type IntoIter = ArrayOrVecSliceIter<T, SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        ArrayOrVecSliceIter(
            self.data
                .into_iter()
                .take(self.range.end)
                .skip(self.range.start),
        )
    }
}

impl<T, const SIZE: usize> Iterator for ArrayOrVecSliceIter<T, SIZE> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<T, const SIZE: usize> DoubleEndedIterator for ArrayOrVecSliceIter<T, SIZE> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

impl<T, const SIZE: usize> ExactSizeIterator for ArrayOrVecSliceIter<T, SIZE> {
    fn len(&self) -> usize {
        self.0.len()
    }
}
