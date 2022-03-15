use std::io;

use thiserror::Error;
use winapi::shared::winerror::ERROR_PARTIAL_COPY;

use crate::error::{ExceptionCode, SyringeError};

#[derive(Debug, Error)]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc")))]
/// An enum repsenting possible errors during remote procedure calls without serialization, deserialization or remote panics.
pub enum RawRpcError {
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unhandled exception inside the target process.
    #[error("remote exception: {}", _0)]
    RemoteException(ExceptionCode),
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
}

impl From<io::Error> for RawRpcError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _)
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

impl From<ExceptionCode> for RawRpcError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

#[cfg(feature = "rpc-raw")]
impl From<RawRpcError> for SyringeError {
    fn from(err: RawRpcError) -> Self {
        match err {
            RawRpcError::Io(err) => Self::Io(err),
            RawRpcError::RemoteException(code) => Self::RemoteException(code),
            RawRpcError::ProcessInaccessible => Self::ProcessInaccessible,
        }
    }
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc")))]
/// An enum repsenting possible errors during remote procedure calls.
pub enum PayloadRpcError {
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unhandled exception inside the target process.
    #[error("remote exception: {}", _0)]
    RemoteException(ExceptionCode),
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an error in the remote procedure.
    #[error("remote procedure error: {}", _0)]
    RemoteProcedure(String),
    /// Variant representing an error while serializing or deserializing.
    #[error("serde error: {}", _0)]
    Serde(#[from] Box<bincode::ErrorKind>),
}

impl From<io::Error> for PayloadRpcError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _)
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

impl From<RawRpcError> for PayloadRpcError {
    fn from(err: RawRpcError) -> Self {
        match err {
            RawRpcError::Io(err) => Self::Io(err),
            RawRpcError::RemoteException(code) => Self::RemoteException(code),
            RawRpcError::ProcessInaccessible => Self::ProcessInaccessible,
        }
    }
}
