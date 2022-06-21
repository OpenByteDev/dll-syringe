use std::{
    fmt::{self, Display},
    io,
};

use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;
use winapi::um::{
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
};

#[cfg(feature = "syringe")]
use winapi::shared::winerror::ERROR_PARTIAL_COPY;

#[derive(Debug, Error)]
/// Error enum representing either a windows api error or a nul error from an invalid interior nul.
pub enum IoOrNulError {
    /// Variant representing an illegal interior nul value.
    #[error("interior nul found")]
    Nul(#[from] widestring::error::ContainsNul<u16>),
    /// Variant representing an windows api error.
    #[error("io error: {}", _0)]
    Io(#[from] io::Error),
}

/// Error enum for errors during a call to [`ProcessModule::get_local_procedure_address`].
///
/// [`ProcessModule::get_local_procedure_address`]: crate::process::ProcessModule::get_local_procedure_address
#[derive(Debug, Error)]
pub enum GetLocalProcedureAddressError {
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

#[derive(Debug, Error)]
/// An error representing either an unhandled exception or an io error.
pub enum ExceptionOrIoError {
    /// Variant representing an io error.
    #[error("remote io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unhandled exception.
    #[error("remote exception: {}", _0)]
    Exception(ExceptionCode),
}

/// Error enum for errors during [`Syringe::load_inject_help_data_for_process`](crate::Syringe::load_inject_help_data_for_process).
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub(crate) enum LoadInjectHelpDataError {
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

#[cfg(feature = "syringe")]
impl From<io::Error> for LoadInjectHelpDataError {
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

/// Error enum for errors during [`Syringe::inject`](crate::Syringe::inject).
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub enum InjectError {
    /// Variant representing an illegal interior nul value in the module path.
    #[error("module path contains illegal interior nul")]
    IllegalPath(#[from] widestring::error::ContainsNul<u16>),
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing an io error inside the target process.
    #[error("remote io error: {}", _0)]
    RemoteIo(io::Error),
    /// Variant representing an unhandled exception inside the target process.
    #[error("remote exception: {}", _0)]
    RemoteException(ExceptionCode),
    /// Variant representing an inaccessible target process.
    /// This can occur if it crashed or was terminated.
    #[error("inaccessible target process")]
    ProcessInaccessible,
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

#[cfg(feature = "syringe")]
impl From<io::Error> for InjectError {
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

#[cfg(feature = "syringe")]
impl From<ExceptionCode> for InjectError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

#[cfg(feature = "syringe")]
impl From<IoOrNulError> for InjectError {
    fn from(err: IoOrNulError) -> Self {
        match err {
            IoOrNulError::Nul(e) => e.into(),
            IoOrNulError::Io(e) => e.into(),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<ExceptionOrIoError> for InjectError {
    fn from(err: ExceptionOrIoError) -> Self {
        match err {
            ExceptionOrIoError::Io(e) => Self::RemoteIo(e),
            ExceptionOrIoError::Exception(e) => Self::RemoteException(e),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<LoadInjectHelpDataError> for InjectError {
    fn from(err: LoadInjectHelpDataError) -> Self {
        match err {
            LoadInjectHelpDataError::Io(e) => Self::Io(e),
            LoadInjectHelpDataError::UnsupportedTarget => Self::UnsupportedTarget,
            LoadInjectHelpDataError::ProcessInaccessible => Self::ProcessInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            LoadInjectHelpDataError::Goblin(e) => Self::Goblin(e),
        }
    }
}

/// Error enum for errors during [`Syringe::eject`](crate::Syringe::eject).
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub enum EjectError {
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing an io error inside the target process.
    #[error("remote io error: {}", _0)]
    RemoteIo(io::Error),
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
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

#[cfg(feature = "syringe")]
impl From<LoadInjectHelpDataError> for EjectError {
    fn from(err: LoadInjectHelpDataError) -> Self {
        match err {
            LoadInjectHelpDataError::Io(e) => Self::Io(e),
            LoadInjectHelpDataError::UnsupportedTarget => Self::UnsupportedTarget,
            LoadInjectHelpDataError::ProcessInaccessible => Self::ProcessInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            LoadInjectHelpDataError::Goblin(e) => Self::Goblin(e),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<io::Error> for EjectError {
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

#[cfg(feature = "syringe")]
impl From<ExceptionCode> for EjectError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

#[cfg(feature = "syringe")]
impl From<ExceptionOrIoError> for EjectError {
    fn from(err: ExceptionOrIoError) -> Self {
        match err {
            ExceptionOrIoError::Io(e) => Self::RemoteIo(e),
            ExceptionOrIoError::Exception(e) => Self::RemoteException(e),
        }
    }
}

/// Error enum for errors during procedure loading.
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub enum LoadProcedureError {
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing an io error inside the target process.
    #[error("remote io error: {}", _0)]
    RemoteIo(io::Error),
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
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

#[cfg(feature = "syringe")]
impl From<LoadInjectHelpDataError> for LoadProcedureError {
    fn from(err: LoadInjectHelpDataError) -> Self {
        match err {
            LoadInjectHelpDataError::Io(e) => Self::Io(e),
            LoadInjectHelpDataError::UnsupportedTarget => Self::UnsupportedTarget,
            LoadInjectHelpDataError::ProcessInaccessible => Self::ProcessInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            LoadInjectHelpDataError::Goblin(e) => Self::Goblin(e),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<io::Error> for LoadProcedureError {
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

#[cfg(feature = "syringe")]
impl From<ExceptionCode> for LoadProcedureError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

#[cfg(feature = "syringe")]
impl From<ExceptionOrIoError> for LoadProcedureError {
    fn from(err: ExceptionOrIoError) -> Self {
        match err {
            ExceptionOrIoError::Io(e) => Self::RemoteIo(e),
            ExceptionOrIoError::Exception(e) => Self::RemoteException(e),
        }
    }
}

/// Error enum encompassing all errors during [`Syringe`](crate::Syringe) operations.
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub enum SyringeError {
    /// Variant representing an illegal interior nul value in the module path.
    #[error("module path contains illegal interior nul")]
    IllegalPath(#[from] widestring::error::ContainsNul<u16>),
    /// Variant representing an io error.
    #[error("io error: {}", _0)]
    Io(io::Error),
    /// Variant representing an unsupported target process.
    #[error("unsupported target process")]
    UnsupportedTarget,
    /// Variant representing an io error inside the target process.
    #[error("remote io error: {}", _0)]
    RemoteIo(io::Error),
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
    /// Variant representing an error while serializing or deserializing.
    #[cfg(feature = "rpc-payload")]
    #[error("serde error: {}", _0)]
    Serde(Box<bincode::ErrorKind>),
    /// Variant representing an error or panic inside a remote payload procedure.
    #[cfg(feature = "rpc-payload")]
    #[error("remote payload error: {}", _0)]
    RemotePayloadProcedure(String),
    /// Variant representing an error while loading an pe file.
    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    #[error("failed to load pe file: {}", _0)]
    Goblin(#[from] goblin::error::Error),
}

#[cfg(feature = "syringe")]
impl From<io::Error> for SyringeError {
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

#[cfg(feature = "syringe")]
impl From<ExceptionCode> for SyringeError {
    fn from(err: ExceptionCode) -> Self {
        Self::RemoteException(err)
    }
}

#[cfg(feature = "syringe")]
impl From<IoOrNulError> for SyringeError {
    fn from(err: IoOrNulError) -> Self {
        match err {
            IoOrNulError::Nul(e) => e.into(),
            IoOrNulError::Io(e) => e.into(),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<ExceptionOrIoError> for SyringeError {
    fn from(err: ExceptionOrIoError) -> Self {
        match err {
            ExceptionOrIoError::Io(e) => Self::RemoteIo(e),
            ExceptionOrIoError::Exception(e) => Self::RemoteException(e),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<InjectError> for SyringeError {
    fn from(err: InjectError) -> Self {
        match err {
            InjectError::IllegalPath(e) => Self::IllegalPath(e),
            InjectError::Io(e) => Self::Io(e),
            InjectError::UnsupportedTarget => Self::UnsupportedTarget,
            InjectError::RemoteIo(e) => Self::RemoteIo(e),
            InjectError::RemoteException(e) => Self::RemoteException(e),
            InjectError::ProcessInaccessible => Self::ProcessInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            InjectError::Goblin(e) => Self::Goblin(e),
        }
    }
}

#[cfg(feature = "syringe")]
impl From<EjectError> for SyringeError {
    fn from(err: EjectError) -> Self {
        match err {
            EjectError::Io(e) => Self::Io(e),
            EjectError::UnsupportedTarget => Self::UnsupportedTarget,
            EjectError::RemoteIo(e) => Self::RemoteIo(e),
            EjectError::RemoteException(e) => Self::RemoteException(e),
            EjectError::ProcessInaccessible => Self::ProcessInaccessible,
            EjectError::ModuleInaccessible => Self::ModuleInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            EjectError::Goblin(e) => Self::Goblin(e),
        }
    }
}

#[cfg(feature = "rpc-core")]
impl From<LoadProcedureError> for SyringeError {
    fn from(err: LoadProcedureError) -> Self {
        match err {
            LoadProcedureError::Io(e) => Self::Io(e),
            LoadProcedureError::UnsupportedTarget => Self::UnsupportedTarget,
            LoadProcedureError::RemoteIo(e) => Self::RemoteIo(e),
            LoadProcedureError::RemoteException(e) => Self::RemoteException(e),
            LoadProcedureError::ProcessInaccessible => Self::ProcessInaccessible,
            LoadProcedureError::ModuleInaccessible => Self::ModuleInaccessible,
            #[cfg(target_arch = "x86_64")]
            #[cfg(feature = "into-x86-from-x64")]
            LoadProcedureError::Goblin(e) => Self::Goblin(e),
        }
    }
}

#[cfg(feature = "rpc-core")]
#[cfg_attr(all(feature = "rpc-core", not(feature = "rpc-raw")), doc(hidden))]
impl From<crate::rpc::RawRpcError> for SyringeError {
    fn from(err: crate::rpc::RawRpcError) -> Self {
        match err {
            crate::rpc::RawRpcError::Io(err) => Self::Io(err),
            crate::rpc::RawRpcError::RemoteException(code) => Self::RemoteException(code),
            crate::rpc::RawRpcError::ProcessInaccessible => Self::ProcessInaccessible,
            crate::rpc::RawRpcError::ModuleInaccessible => Self::ModuleInaccessible,
        }
    }
}

#[cfg(feature = "rpc-payload")]
#[cfg_attr(all(feature = "rpc-core", not(feature = "rpc-raw")), doc(hidden))]
impl From<crate::rpc::PayloadRpcError> for SyringeError {
    fn from(err: crate::rpc::PayloadRpcError) -> Self {
        match err {
            crate::rpc::PayloadRpcError::Io(e) => Self::Io(e),
            crate::rpc::PayloadRpcError::RemoteException(e) => Self::RemoteException(e),
            crate::rpc::PayloadRpcError::ProcessInaccessible => Self::ProcessInaccessible,
            crate::rpc::PayloadRpcError::ModuleInaccessible => Self::ModuleInaccessible,
            crate::rpc::PayloadRpcError::RemoteProcedure(e) => Self::RemotePayloadProcedure(e),
            crate::rpc::PayloadRpcError::Serde(e) => Self::Serde(e),
        }
    }
}

/// Error enum encompassing all errors during syringe operations in a nested format.
#[derive(Debug, Error)]
#[cfg(feature = "syringe")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub enum SyringeOperationError {
    /// Variant representing an error while injecting a module.
    #[error("inject error: {}", _0)]
    Inject(#[from] InjectError),
    /// Variant representing an error while ejecting a module.
    #[error("eject error: {}", _0)]
    Eject(#[from] EjectError),
    /// Variant representing an error while using payload rpc.
    #[cfg(feature = "rpc-payload")]
    #[error("payload rpc error: {}", _0)]
    PayloadProcedureCall(#[from] crate::rpc::PayloadRpcError),
    /// Variant representing an error while using raw rpc.
    #[cfg(feature = "rpc-raw")]
    #[error("raw rpc error: {}", _0)]
    RawProcedureCall(#[from] crate::rpc::RawRpcError),
    /// Variant representing an error while using rpc.
    #[cfg(feature = "rpc-core")]
    #[error("procedure load error: {}", _0)]
    ProcedureLoad(#[from] LoadProcedureError),
}
