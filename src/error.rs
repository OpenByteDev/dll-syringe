use std::{
    fmt::{self, Display},
    io,
};

use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;
use winapi::{
    shared::winerror::ERROR_PARTIAL_COPY,
    um::{
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
    },
};

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
        if cfg!(target_arch = "x86_64") && err.raw_os_error() == Some(ERROR_PARTIAL_COPY as _)
            || err.kind() == io::ErrorKind::PermissionDenied
        {
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

#[derive(
    Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
#[repr(u32)]
/// Codes for unhandled windows exceptions from [msdn](https://docs.microsoft.com/en-us/windows/win32/debug/getexceptioncode).
pub enum ExceptionCode {
    /// The thread attempts to read from or write to a virtual address for which it does not have access.
    AccessViolation = EXCEPTION_ACCESS_VIOLATION,
    /// The thread attempts to access an array element that is out of bounds, and the underlying hardware supports bounds checking.
    ArrayBoundsExceeded = EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
    /// A breakpoint is encountered.
    Breakpoint = EXCEPTION_BREAKPOINT,
    /// The thread attempts to read or write data that is misaligned on hardware that does not provide alignment.
    /// For example, 16-bit values must be aligned on 2-byte boundaries, 32-bit values on 4-byte boundaries, and so on.
    DatatypeMisalignment = EXCEPTION_DATATYPE_MISALIGNMENT,
    /// One of the operands in a floating point operation is denormal.
    /// A denormal value is one that is too small to represent as a standard floating point value.
    FltDenormalOperand = EXCEPTION_FLT_DENORMAL_OPERAND,
    /// The thread attempts to divide a floating point value by a floating point divisor of 0 (zero).
    FltDivideByZero = EXCEPTION_FLT_DIVIDE_BY_ZERO,
    /// The result of a floating point operation cannot be represented exactly as a decimal fraction.
    FltInexactResult = EXCEPTION_FLT_INEXACT_RESULT,
    /// A floating point exception that is not included in this list.
    FltInvalidOperation = EXCEPTION_FLT_INVALID_OPERATION,
    /// The exponent of a floating point operation is greater than the magnitude allowed by the corresponding type.
    FltOverflow = EXCEPTION_FLT_OVERFLOW,
    /// The stack has overflowed or underflowed, because of a floating point operation.
    FltStackCheck = EXCEPTION_FLT_STACK_CHECK,
    /// The exponent of a floating point operation is less than the magnitude allowed by the corresponding type.
    FltUnderflow = EXCEPTION_FLT_UNDERFLOW,
    /// The thread accessed memory allocated with the PAGE_GUARD modifier.
    GuardPage = EXCEPTION_GUARD_PAGE,
    /// The thread tries to execute an invalid instruction.
    IllegalInstruction = EXCEPTION_ILLEGAL_INSTRUCTION,
    /// The thread tries to access a page that is not present, and the system is unable to load the page.
    /// For example, this exception might occur if a network connection is lost while running a program over a network.
    InPageError = EXCEPTION_IN_PAGE_ERROR,
    /// The thread attempts to divide an integer value by an integer divisor of 0 (zero).
    IntegerDivideByZero = EXCEPTION_INT_DIVIDE_BY_ZERO,
    /// The result of an integer operation creates a value that is too large to be held by the destination register.
    /// In some cases, this will result in a carry out of the most significant bit of the result.
    /// Some operations do not set the carry flag.
    IntegerOverflow = EXCEPTION_INT_OVERFLOW,
    /// An exception handler returns an invalid disposition to the exception dispatcher.
    /// Programmers using a high-level language such as C should never encounter this exception.
    InvalidDisposition = EXCEPTION_INVALID_DISPOSITION,
    /// The thread used a handle to a kernel object that was invalid (probably because it had been closed.)
    InvalidHandle = EXCEPTION_INVALID_HANDLE,
    /// The thread attempts to continue execution after a non-continuable exception occurs.
    NoncontinuableException = EXCEPTION_NONCONTINUABLE_EXCEPTION,
    /// The thread attempts to execute an instruction with an operation that is not allowed in the current computer mode.
    PrivilegedInstruction = EXCEPTION_PRIV_INSTRUCTION,
    /// A trace trap or other single instruction mechanism signals that one instruction is executed.
    SingleStep = EXCEPTION_SINGLE_STEP,
    /// The thread uses up its stack.
    StackOverflow = EXCEPTION_STACK_OVERFLOW,
    /// A frame consolidation has been executed.
    UnwindConsolidate = STATUS_UNWIND_CONSOLIDATE,
}

impl ExceptionCode {
    /// Try to interpret the given code as a windows exception code.
    pub fn try_from_code(code: u32) -> Result<Self, TryFromPrimitiveError<Self>> {
        Self::try_from_primitive(code)
    }
    /// Returns the underlying windows exception code.
    #[must_use]
    pub fn code(self) -> u32 {
        self.into()
    }
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
