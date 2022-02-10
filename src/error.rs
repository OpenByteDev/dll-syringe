use std::{
    fmt::{self, Display},
    io,
};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use winapi::{um::{
    minwinbase::{
        EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ARRAY_BOUNDS_EXCEEDED, EXCEPTION_BREAKPOINT,
        EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_FLT_DENORMAL_OPERAND,
        EXCEPTION_FLT_DIVIDE_BY_ZERO, EXCEPTION_FLT_INEXACT_RESULT,
        EXCEPTION_FLT_INVALID_OPERATION, EXCEPTION_FLT_OVERFLOW, EXCEPTION_FLT_STACK_CHECK,
        EXCEPTION_FLT_UNDERFLOW, EXCEPTION_GUARD_PAGE, EXCEPTION_ILLEGAL_INSTRUCTION,
        EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_INT_OVERFLOW, EXCEPTION_INVALID_DISPOSITION,
        EXCEPTION_INVALID_HANDLE, EXCEPTION_IN_PAGE_ERROR, EXCEPTION_NONCONTINUABLE_EXCEPTION,
        EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_SINGLE_STEP, EXCEPTION_STACK_OVERFLOW,
    },
    winnt::STATUS_UNWIND_CONSOLIDATE,
}, shared::winerror::ERROR_PARTIAL_COPY};

#[derive(Debug, Error)]
/// Error enum representing either a windows api error or a nul error from an invalid interior nul.
pub enum IoOrNulError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::NulError<u16>),
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
}

impl From<get_last_error::Win32Error> for IoOrNulError {
    fn from(err: get_last_error::Win32Error) -> Self {
        Self::Io(err.into())
    }
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
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported remote target process")]
    UnsupportedRemoteTarget,
}

impl From<get_last_error::Win32Error> for GetLocalProcedureError {
    fn from(err: get_last_error::Win32Error) -> Self {
        Self::Io(err.into())
    }
}

// TODO: add more specialized error variants
/// Error enum for errors during syringe operations like injection, ejection or remote procedure calling.
#[derive(Debug, Error)]
pub enum SyringeError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::NulError<u16>),
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing a windows api error inside the target process.
    #[error("remote io error: {}", _0)]
    RemoteIo(io::Error),
    /// Variant representing a windows api error inside the target process.
    #[error("remote exception: {}", _0)]
    RemoteException(ExceptionCode),
    /// Variant representing an inaccessible target process. This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into_x86_from_x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

impl From<get_last_error::Win32Error> for SyringeError {
    fn from(err: get_last_error::Win32Error) -> Self {
        io::Error::from(err).into()
    }
}

impl From<io::Error> for SyringeError {
    fn from(err: io::Error) -> Self {
        if cfg!(target_arch = "x86_64") && err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _) || 
            err.kind() == io::ErrorKind::PermissionDenied {
            Self::ProcessInaccessible
        } else {
            Self::Io(err)
        }
    }
}

impl From<IoOrNulError> for SyringeError {
    fn from(err: IoOrNulError) -> Self {
        match err {
            IoOrNulError::Nul(e) => e.into(),
            IoOrNulError::Io(e) => e.into(),
        }
    }
}

// from https://docs.microsoft.com/en-us/windows/win32/debug/getexceptioncode
#[derive(Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum ExceptionCode {
    AccessViolation = EXCEPTION_ACCESS_VIOLATION,
    ArrayBoundsExceeded = EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
    Breakpoint = EXCEPTION_BREAKPOINT,
    DatatypeMisalignment = EXCEPTION_DATATYPE_MISALIGNMENT,
    FltDenormalOperand = EXCEPTION_FLT_DENORMAL_OPERAND,
    FltDivideByZero = EXCEPTION_FLT_DIVIDE_BY_ZERO,
    FltInexactResult = EXCEPTION_FLT_INEXACT_RESULT,
    FltInvalidOperation = EXCEPTION_FLT_INVALID_OPERATION,
    FltOverflow = EXCEPTION_FLT_OVERFLOW,
    FltStackCheck = EXCEPTION_FLT_STACK_CHECK,
    FltUnderflow = EXCEPTION_FLT_UNDERFLOW,
    GuardPage = EXCEPTION_GUARD_PAGE,
    IllegalInstruction = EXCEPTION_ILLEGAL_INSTRUCTION,
    InPageError = EXCEPTION_IN_PAGE_ERROR,
    IntegerDivideByZero = EXCEPTION_INT_DIVIDE_BY_ZERO,
    IntegerOverflow = EXCEPTION_INT_OVERFLOW,
    InvalidDisposition = EXCEPTION_INVALID_DISPOSITION,
    InvalidHandle = EXCEPTION_INVALID_HANDLE,
    NoncontinuableException = EXCEPTION_NONCONTINUABLE_EXCEPTION,
    PrivilegedInstruction = EXCEPTION_PRIV_INSTRUCTION,
    SingleStep = EXCEPTION_SINGLE_STEP,
    StackOverflow = EXCEPTION_STACK_OVERFLOW,
    UnwindConsolidate = STATUS_UNWIND_CONSOLIDATE,
}

impl Display for ExceptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // These error messages were collected using https://stackoverflow.com/a/43961146/6304917 and https://stackoverflow.com/a/7915329/6304917
        // They are hardcoded as they are unlikely appear very often and would require a lot of extra code
        // Additionally, the messages returned from the methods above are sometimes unusable and inconsitently formatted.

        match *self {
            Self::AccessViolation => write!(f, "Invalid access to memory location."),
            Self::ArrayBoundsExceeded => write!(f, "Array bounds exceeded."),
            Self::Breakpoint => write!(f, "A breakpoint has been reached."),
            Self::DatatypeMisalignment => write!(f, "A datatype misalignment was detected in a load or store instruction."),
            Self::FltDenormalOperand => write!(f, "Floating-point denormal operand."),
            Self::FltDivideByZero => write!(f, "Floating-point division by zero."),
            Self::FltInexactResult => write!(f, "Floating-point inexact result."),
            Self::FltInvalidOperation => write!(f, "Floating-point invalid operation."),
            Self::FltOverflow => write!(f, "Floating-point overflow."),
            Self::FltStackCheck => write!(f, "Floating-point stack check."),
            Self::FltUnderflow => write!(f, "Floating-point underflow."),
            Self::GuardPage => write!(f, "A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed."),
            Self::IllegalInstruction => write!(f, "An attempt was made to execute an illegal instruction."),
            Self::InPageError => write!(f, "Error performing inpage operation."),
            Self::IntegerDivideByZero => write!(f, "Integer division by zero."),
            Self::IntegerOverflow => write!(f, "Integer overflow."),
            Self::InvalidDisposition => write!(f, "An invalid exception disposition was returned by an exception handler."),
            Self::InvalidHandle => write!(f, "The handle is invalid."),
            Self::NoncontinuableException => write!(f, "Windows cannot continue from this exception."),
            Self::PrivilegedInstruction => write!(f, "Privileged instruction."),
            Self::SingleStep => write!(f, "A single step or trace operation has just been completed."),
            Self::StackOverflow => write!(f, "Recursion too deep; the stack overflowed."),
            Self::UnwindConsolidate => write!(f, "A frame consolidation has been executed."),
        }
    }
}
