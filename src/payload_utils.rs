use std::{
    ffi::c_void,
    io::{self, Write},
    panic::{self, AssertUnwindSafe},
    slice,
};

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    process::{memory::ProcessMemoryBuffer, BorrowedProcess, Process},
    ArgAndResultBufInfo,
};

/// A macro for defining an exported function that can be used with [`RemotePayloadProcedure`](crate::rpc::RemotePayloadProcedure).
pub use dll_syringe_macros::payload_procedure;

pub fn __payload_procedure_helper<A: DeserializeOwned, R: Serialize>(
    buf_info_ptr: *mut c_void,
    f: impl FnOnce(A) -> R,
) {
    let buf_info_ptr = buf_info_ptr.cast::<ArgAndResultBufInfo>();
    let buf_info = unsafe { &mut *buf_info_ptr };
    let buf = unsafe { slice::from_raw_parts_mut(buf_info.data as *mut u8, buf_info.len as usize) };

    let result = panic::catch_unwind(AssertUnwindSafe(|| payload_procedure_helper_inner(buf, f)));

    match result {
        Ok(Ok(result_buf)) => unsafe {
            (*buf_info_ptr).data = result_buf.as_ptr() as u64;
            (*buf_info_ptr).len = result_buf.len() as u64;
        },
        err => {
            unsafe {
                (*buf_info_ptr).is_error = true;
            }

            let message = match err {
                Ok(Err(e)) => e.to_string(),
                Err(e) => match e.downcast_ref::<&'static str>() {
                    Some(s) => s.to_string(),
                    None => match e.downcast::<String>() {
                        Ok(s) => *s,
                        Err(_) => "unknown panic".to_string(),
                    },
                },
                _ => unreachable!(),
            };

            let Ok(mut error_buf) = allocate_local_process_memory(message.len()) else {
                return;
            };
            unsafe {
                (*buf_info_ptr).data = error_buf.as_ptr() as u64;
                (*buf_info_ptr).len = error_buf.len() as u64;
            }
            let _ = write!(error_buf, "{message}");
        }
    }
}

fn payload_procedure_helper_inner<A: DeserializeOwned, R: Serialize>(
    buf: &mut [u8],
    f: impl FnOnce(A) -> R,
) -> Result<&'_ mut [u8], PayloadProcedureHelperError> {
    let config = cu_bincode::config::standard();

    let args = cu_bincode::serde::decode_from_slice(buf, config)?.0;

    let result = f(args);

    let mut size_writer = cu_bincode::enc::write::SizeWriter::default();
    cu_bincode::serde::encode_into_writer(&result, &mut size_writer, config)?;
    let required_buf_len = size_writer.bytes_written;
    let result_buf = if required_buf_len > buf.len() {
        allocate_local_process_memory(required_buf_len)?
    } else {
        buf
    };

    cu_bincode::serde::encode_into_slice(result, &mut *result_buf, config)?;

    Ok(result_buf)
}

fn allocate_local_process_memory(len: usize) -> io::Result<&'static mut [u8]> {
    let current_process = BorrowedProcess::current();
    let result_memory = ProcessMemoryBuffer::allocate_data(current_process, len)?;
    Ok(result_memory.into_dangling_local_slice().unwrap())
}

#[derive(Debug, Error)]
enum PayloadProcedureHelperError {
    #[error("serializeerror: {0}")]
    Serialize(#[from] cu_bincode::error::EncodeError),
    #[error("deserialize error: {0}")]
    Deserialize(#[from] cu_bincode::error::DecodeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}
