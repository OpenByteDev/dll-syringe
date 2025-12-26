use std::io;

use thiserror::Error;
use winapi::shared::winerror::ERROR_PARTIAL_COPY;

use crate::error::ExceptionCode;

#[derive(Debug, Error)]
#[cfg(feature = "rpc-core")]
#[cfg_attr(all(feature = "rpc-core", not(feature = "rpc-raw")), doc(hidden))]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-raw")))]
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
    /// Variant representing an inaccessible target module.
    /// This can occur if the target module was ejected or unloaded.
    #[error("inaccessible target module")]
    ModuleInaccessible,
}

#[cfg(feature = "rpc-core")]
#[cfg_attr(all(feature = "rpc-core", not(feature = "rpc-raw")), doc(hidden))]
impl From<io::Error> for RawRpcError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY.cast_signed())
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

#[cfg(feature = "rpc-core")]
#[cfg_attr(all(feature = "rpc-core", not(feature = "rpc-raw")), doc(hidden))]
impl From<ExceptionCode> for RawRpcError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

/// Error enum for errors during serialization or deserialization of rpc arguments.
#[derive(Debug, Error)]
#[cfg(feature = "rpc-payload")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-payload")))]
pub enum SerdeError {
    /// Variant representing an error during serialization.
    #[error("serialize error: {}", _0)]
    Serialize(#[from] bincode::error::EncodeError),
    /// Variant representing an error during deserialization.
    #[error("deserialize error: {}", _0)]
    Deserialize(#[from] bincode::error::DecodeError),
}

#[derive(Debug, Error)]
#[cfg(feature = "rpc-payload")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-payload")))]
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
    /// Variant representing an inaccessible target module.
    /// This can occur if the target module was ejected or unloaded.
    #[error("inaccessible target module")]
    ModuleInaccessible,
    /// Variant representing an error in the remote procedure.
    #[error("remote procedure error: {}", _0)]
    RemoteProcedure(String),
    /// Variant representing an error while serializing or deserializing.
    #[error("serde error: {}", _0)]
    Serde(#[from] SerdeError),
}

#[cfg(feature = "rpc-payload")]
impl From<bincode::error::EncodeError> for PayloadRpcError {
    fn from(err: bincode::error::EncodeError) -> Self {
        Self::Serde(SerdeError::Serialize(err))
    }
}

#[cfg(feature = "rpc-payload")]
impl From<bincode::error::DecodeError> for PayloadRpcError {
    fn from(err: bincode::error::DecodeError) -> Self {
        Self::Serde(SerdeError::Deserialize(err))
    }
}

#[cfg(feature = "rpc-payload")]
impl From<io::Error> for PayloadRpcError {
    fn from(err: io::Error) -> Self {
        if err.raw_os_error() == Some(ERROR_PARTIAL_COPY.cast_signed())
            || err.kind() == io::ErrorKind::PermissionDenied
        {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

#[cfg(all(feature = "rpc-payload", feature = "rpc-raw"))]
impl From<RawRpcError> for PayloadRpcError {
    fn from(err: RawRpcError) -> Self {
        match err {
            RawRpcError::Io(err) => Self::Io(err),
            RawRpcError::RemoteException(code) => Self::RemoteException(code),
            RawRpcError::ProcessInaccessible => Self::ProcessInaccessible,
            RawRpcError::ModuleInaccessible => Self::ModuleInaccessible,
        }
    }
}
