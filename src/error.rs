use std::io;

use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum Win32OrNulError {
        Nul(source: widestring::NulError<u16>) {
            from()
            display("Invalid nul value in argument: {}", source)
            source(source)
        }
        Win32(source: rust_win32error::Win32Error) {
            from()
            display("Windows API call failed: {}", source)
            source(source)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ProcedureLoadError {
        Nul(source: std::ffi::NulError) {
            from()
            display("Invalid nul value in argument: {}", source)
            source(source)
        }
        Win32(source: rust_win32error::Win32Error) {
            from()
            display("Windows API call failed: {}", source)
            source(source)
        }
        UnsupportedTarget {
            display("The requested operation is not supported for the target process.")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ModuleFromPathError {
        Nul(source: widestring::NulError<u16>) {
            from()
            display("Invalid nul value in argument: {}", source)
            source(source)
        }
        Win32(source: rust_win32error::Win32Error) {
            from()
            display("Windows API call failed: {}", source)
            source(source)
        }
        Io(source: io::Error) {
            from()
            display("Io error: {}", source)
            source(source)
        }
    }
}

impl From<Win32OrNulError> for ModuleFromPathError {
    fn from(err: Win32OrNulError) -> Self {
        match err {
            Win32OrNulError::Nul(e) => ModuleFromPathError::Nul(e),
            Win32OrNulError::Win32(e) => ModuleFromPathError::Win32(e),
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum InjectError {
        Nul(source: widestring::NulError<u16>) {
            from()
            display("Invalid nul value in argument: {}", source)
            source(source)
        }
        Win32(source: rust_win32error::Win32Error) {
            from()
            display("Windows API call failed: {}", source)
            source(source)
        }
        UnsupportedTarget {
            display("The requested operation is not supported for the target process.")
        }
        RemoteOperationFailed {
            display("An operation failed inside the remote process.")
        }
        Io(source: io::Error) {
            from()
            display("Io error: {}", source)
            source(source)
        }
        #[cfg(target_arch = "x86_64")]
        #[cfg(feature = "into_x86_from_x64")]
        Goblin(source: goblin::error::Error) {
            display("Goblin failed to load pe file: {}", source)
            source(source)
        }
    }
}

// This cannot be done with from() like for the other error types as goblin is only present
// on x64 with the into_x86_from_x64 feature and quick_error includes the From impl
// unconditionally
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "into_x86_from_x64")]
impl From<goblin::error::Error> for InjectError {
    fn from(source: goblin::error::Error) -> Self {
        InjectError::Goblin(source)
    }
}

impl From<Win32OrNulError> for InjectError {
    fn from(err: Win32OrNulError) -> Self {
        match err {
            Win32OrNulError::Nul(e) => InjectError::Nul(e),
            Win32OrNulError::Win32(e) => InjectError::Win32(e),
        }
    }
}

impl From<ModuleFromPathError> for InjectError {
    fn from(err: ModuleFromPathError) -> Self {
        match err {
            ModuleFromPathError::Nul(e) => InjectError::Nul(e),
            ModuleFromPathError::Win32(e) => InjectError::Win32(e),
            ModuleFromPathError::Io(e) => InjectError::Io(e),
        }
    }
}
