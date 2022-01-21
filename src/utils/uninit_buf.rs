use std::{
    ffi::OsString,
    mem::MaybeUninit,
    ops::{Deref, DerefMut, RangeBounds},
    path::PathBuf,
};

use widestring::{error::MissingNulTerminator, U16CStr, U16Str};
use winapi::shared::minwindef::MAX_PATH;

pub(crate) struct UninitArrayBuf<T, const SIZE: usize>([MaybeUninit<T>; SIZE]);

impl<T, const SIZE: usize> UninitArrayBuf<T, SIZE> {
    pub const fn new() -> Self {
        Self(MaybeUninit::uninit_array::<SIZE>())
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[allow(dead_code)]
    pub const fn as_ptr(&self) -> *const T {
        self.0.as_ptr().cast()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.0.as_mut_ptr().cast()
    }

    pub unsafe fn assume_init_all(self) -> [T; SIZE] {
        unsafe { MaybeUninit::array_assume_init(self.0) }
    }

    pub unsafe fn assume_init_slice(&self, range: impl RangeBounds<usize>) -> &[T] {
        // TODO: this has to be easier some other way
        let slice = &(&self.0)[(range.start_bound().cloned(), range.end_bound().cloned())];
        unsafe { MaybeUninit::slice_assume_init_ref(slice) }
    }

    #[allow(dead_code)]
    pub unsafe fn assume_init_slice_mut(&mut self, range: impl RangeBounds<usize>) -> &mut [T] {
        // TODO: this has to be easier some other way
        let slice = &mut (&mut self.0)[(range.start_bound().cloned(), range.end_bound().cloned())];
        unsafe { MaybeUninit::slice_assume_init_mut(slice) }
    }
}

#[cfg(windows)]
pub(crate) struct WinPathBuf(UninitArrayBuf<u16, MAX_PATH>);

#[cfg(windows)]
impl WinPathBuf {
    pub const fn new() -> Self {
        Self(UninitArrayBuf::new())
    }

    pub unsafe fn assume_init_os_string(&self, len: usize) -> OsString {
        unsafe { self.assume_init_u16_str(len) }.to_os_string()
    }

    pub unsafe fn assume_init_path_buf(&self, len: usize) -> PathBuf {
        unsafe { self.assume_init_os_string(len) }.into()
    }

    pub unsafe fn assume_init_u16_str(&self, len: usize) -> &U16Str {
        let slice = unsafe { self.0.assume_init_slice(..len) };
        U16Str::from_slice(slice)
    }

    #[allow(dead_code)]
    pub unsafe fn assume_init_u16_str_with_nul(
        &self,
        len: usize,
    ) -> Result<&U16CStr, MissingNulTerminator> {
        let slice = unsafe { self.0.assume_init_slice(..len) };
        U16CStr::from_slice_truncate(slice)
    }

    #[allow(dead_code)]
    pub unsafe fn assume_init_u16_str_with_nul_unchecked(&self, len: usize) -> &U16CStr {
        let slice = unsafe { self.0.assume_init_slice(..len) };
        unsafe { U16CStr::from_slice_unchecked(slice) }
    }
}

impl Deref for WinPathBuf {
    type Target = UninitArrayBuf<u16, MAX_PATH>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WinPathBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
