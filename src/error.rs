use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
/// Error enum representing either a win32 api error or a nul error from an invalid interior nul.
pub enum Win32OrNulError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::NulError<u16>),
    /// Variant representing an windows api error.
    #[error("windows api error: {}", _0)]
    Win32(#[from] rust_win32error::Win32Error),
}

/// Error enum for errors during a call to [`ProcessModule::get_local_procedure`].
///
/// [`ProcessModule::get_local_procedure`]: crate::ProcessModule::get_local_procedure
#[derive(Debug, Error)]
pub enum GetLocalProcedureError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] std::ffi::NulError),
    /// Variant representing an windows api error.
    #[error("windows api error: {}", _0)]
    Win32(#[from] rust_win32error::Win32Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported remote target process")]
    UnsupportedRemoteTarget,
}

/// Error enum for errors during a call to [`ProcessModule::find_by_path`] and related methods.
///
/// [`ProcessModule::find_by_path`]: crate::ProcessModule::find_by_path
#[derive(Debug, Error)]
pub enum FindModuleByPathError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::NulError<u16>),
    /// Variant representing an windows api error.
    #[error("windows api error: {}", _0)]
    Win32(#[from] rust_win32error::Win32Error),
    /// Variant representing a general io error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
}

impl From<Win32OrNulError> for FindModuleByPathError {
    fn from(err: Win32OrNulError) -> Self {
        match err {
            Win32OrNulError::Nul(e) => Self::Nul(e),
            Win32OrNulError::Win32(e) => Self::Win32(e),
        }
    }
}

// TODO: add more specialized error variants
/// Error enum for errors during syringe operations like injection, ejection or remote procedure calling.
#[derive(Debug, Error)]
pub enum SyringeError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::NulError<u16>),
    /// Variant representing an windows api error.
    #[error("windows api error: {}", _0)]
    Win32(#[from] rust_win32error::Win32Error),
    /// Variant representing a general io error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing a failed operation inside the target process.
    #[error("remote operation failed inside target process")]
    RemoteOperationFailed,
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into_x86_from_x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

impl From<Win32OrNulError> for SyringeError {
    fn from(err: Win32OrNulError) -> Self {
        match err {
            Win32OrNulError::Nul(e) => Self::Nul(e),
            Win32OrNulError::Win32(e) => Self::Win32(e),
        }
    }
}

impl From<FindModuleByPathError> for SyringeError {
    fn from(err: FindModuleByPathError) -> Self {
        match err {
            FindModuleByPathError::Nul(e) => Self::Nul(e),
            FindModuleByPathError::Win32(e) => Self::Win32(e),
            FindModuleByPathError::Io(e) => Self::Io(e),
        }
    }
}
