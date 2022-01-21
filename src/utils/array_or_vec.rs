use std::ops::{Bound, Deref, RangeBounds};

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

#[derive(Debug)]
pub(crate) struct ArrayOrVecSlice<T, const SIZE: usize> {
    data: ArrayOrVec<T, SIZE>,
    range: (Bound<usize>, Bound<usize>),
}

impl<T, const SIZE: usize> ArrayOrVecSlice<T, SIZE> {
    pub fn from_array(array: [T; SIZE], range: impl RangeBounds<usize>) -> Self {
        Self {
            data: ArrayOrVec::Array(array),
            range: (range.start_bound().cloned(), range.end_bound().cloned()),
        }
    }

    pub fn from_vec(vec: Vec<T>, range: impl RangeBounds<usize>) -> Self {
        Self {
            data: ArrayOrVec::Vec(vec),
            range: (range.start_bound().cloned(), range.end_bound().cloned()),
        }
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[T] {
        match self.data {
            ArrayOrVec::Array(ref array) => &array[self.range],
            ArrayOrVec::Vec(ref vec) => &vec[self.range],
        }
    }
}

impl<T, const SIZE: usize> AsRef<[T]> for ArrayOrVecSlice<T, SIZE> {
    fn as_ref(&self) -> &[T] {
        &self.data.as_ref()[self.range]
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
            data: array_or_vec,
            range: (Bound::Unbounded, Bound::Unbounded),
        }
    }
}
