use std::{cmp, io, mem::MaybeUninit, ops::RangeBounds, path::PathBuf};

use winapi::shared::minwindef::MAX_PATH;

pub(crate) struct UninitArrayBuf<T, const SIZE: usize>([MaybeUninit<T>; SIZE]);

impl<T, const SIZE: usize> UninitArrayBuf<T, SIZE> {
    pub const fn new() -> Self {
        Self(MaybeUninit::uninit_array::<SIZE>())
    }

    pub const fn as_slice(&self) -> &[MaybeUninit<T>] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [MaybeUninit<T>] {
        self.0.as_mut_slice()
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

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
        let slice = &self.as_slice()[(range.start_bound().cloned(), range.end_bound().cloned())];
        unsafe { MaybeUninit::slice_assume_init_ref(slice) }
    }

    #[allow(dead_code)]
    pub unsafe fn assume_init_slice_mut(&mut self, range: impl RangeBounds<usize>) -> &mut [T] {
        // TODO: this has to be easier some other way
        let slice =
            &mut self.as_mut_slice()[(range.start_bound().cloned(), range.end_bound().cloned())];
        unsafe { MaybeUninit::slice_assume_init_mut(slice) }
    }
}

pub enum FillPathBufResult {
    BufTooSmall { size_hint: Option<usize> },
    Success { actual_len: usize },
    Error(io::Error),
}

pub fn win_fill_path_buf_helper(
    mut f: impl FnMut(*mut u16, usize) -> FillPathBufResult,
) -> Result<PathBuf, io::Error> {
    let mut buf = UninitArrayBuf::<u16, MAX_PATH>::new();
    match f(buf.as_mut_ptr(), buf.len()) {
        FillPathBufResult::BufTooSmall { mut size_hint } => {
            let mut vec_buf = Vec::new();
            let mut buf_len = buf.len();
            loop {
                buf_len = cmp::max(buf_len.saturating_mul(2), size_hint.unwrap_or(0));
                vec_buf.resize(buf_len, MaybeUninit::uninit());
                match f(vec_buf[0].as_mut_ptr(), vec_buf.len()) {
                    FillPathBufResult::Success { actual_len } => {
                        let slice =
                            unsafe { MaybeUninit::slice_assume_init_ref(&vec_buf[..actual_len]) };
                        let wide_str = widestring::U16Str::from_slice(slice);
                        return Ok(wide_str.to_os_string().into());
                    }
                    FillPathBufResult::Error(e) => return Err(e),
                    FillPathBufResult::BufTooSmall {
                        size_hint: new_size_hint,
                    } => size_hint = new_size_hint,
                }
            }
        }
        FillPathBufResult::Success { actual_len } => {
            let slice = unsafe { buf.assume_init_slice(..actual_len) };
            let wide_str = widestring::U16Str::from_slice(slice);
            Ok(wide_str.to_os_string().into())
        }
        FillPathBufResult::Error(e) => Err(e),
    }
}
