use std::{cmp, io, mem::MaybeUninit, path::PathBuf};

use winapi::shared::minwindef::MAX_PATH;

use super::ArrayBuf;

pub enum FillPathBufResult {
    BufTooSmall { size_hint: Option<usize> },
    Success { actual_len: usize },
    Error(io::Error),
}

pub fn win_fill_path_buf_helper(
    mut f: impl FnMut(*mut u16, usize) -> FillPathBufResult,
) -> Result<PathBuf, io::Error> {
    let mut buf = ArrayBuf::<u16, MAX_PATH>::new_uninit();
    match f(buf.as_mut_ptr(), buf.capacity()) {
        FillPathBufResult::BufTooSmall { mut size_hint } => {
            let mut vec_buf = Vec::new();
            let mut buf_len = buf.capacity();
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
            unsafe { buf.set_len(actual_len) };
            let wide_str = widestring::U16Str::from_slice(buf.as_slice());
            Ok(wide_str.to_os_string().into())
        }
        FillPathBufResult::Error(e) => Err(e),
    }
}
