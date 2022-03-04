use std::{
    ffi::{CStr, CString, OsString},
    io,
    path::{Path, PathBuf},
    ptr::NonNull,
};

use crate::{
    error::{GetLocalProcedureAddressError, IoOrNulError},
    process::BorrowedProcess,
    utils::{win_fill_path_buf_helper, FillPathBufResult},
};
use path_absolutize::Absolutize;
use widestring::{U16CStr, U16CString};
use winapi::{
    shared::{
        minwindef::{FARPROC, HINSTANCE__, HMODULE},
        winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_MOD_NOT_FOUND},
    },
    um::{
        libloaderapi::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW},
    },
};

use super::{OwnedProcess, Process};

/// A handle to a process module.
///
/// # Note
/// This is not a [`HANDLE`](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types#HANDLE)
/// but a [`HMODULE`](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types#HMODULE)
/// which is the base address of a loaded module.
pub type ModuleHandle = HMODULE;

/// A struct representing a loaded module of a running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessModule<P: Process> {
    handle: NonNull<HINSTANCE__>,
    process: P,
}

/// Type alias for a [`ProcessModule`] that owns its [`Process`] instance.
pub type OwnedProcessModule = ProcessModule<OwnedProcess>;
/// Type alias for a [`ProcessModule`] that does **NOT** own its [`Process`] instance.
pub type BorrowedProcessModule<'a> = ProcessModule<BorrowedProcess<'a>>;

unsafe impl<P: Process + Send> Send for ProcessModule<P> {}
unsafe impl<P: Process + Sync> Sync for ProcessModule<P> {}

impl<P: Process> ProcessModule<P> {
    /// Contructs a new instance from the given module handle and its corresponding process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process.
    /// (and stays that way while using the returned instance).
    pub unsafe fn new_unchecked(handle: ModuleHandle, process: P) -> Self {
        let handle = unsafe { NonNull::new_unchecked(handle) };
        Self { handle, process }
    }

    /// Contructs a new instance from the given module handle loaded in the current process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process.
    /// (and stays that way while using the returned instance).
    pub unsafe fn new_local_unchecked(handle: ModuleHandle) -> Self {
        unsafe { ProcessModule::new_unchecked(handle, P::current()) }
    }

    /// Returns a borrowed instance of this module.
    pub fn borrowed(&self) -> BorrowedProcessModule<'_> {
        ProcessModule {
            handle: self.handle,
            process: self.process.borrowed(),
        }
    }

    /// Searches for a module with the given name or path in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find(
        module_name_or_path: impl AsRef<Path>,
        process: P,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        let module_name_or_path = module_name_or_path.as_ref();
        if module_name_or_path.parent().is_some() {
            Self::find_by_path(module_name_or_path, process)
        } else {
            Self::find_by_name(module_name_or_path, process)
        }
    }

    /// Searches for a module with the given name in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_name(
        module_name: impl AsRef<Path>,
        process: P,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        if process.is_current() {
            Self::find_local_by_name(module_name)
        } else {
            Self::_find_remote_by_name(module_name, process)
        }
    }

    /// Searches for a module with the given path in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_path(
        module_path: impl AsRef<Path>,
        process: P,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        if process.is_current() {
            Self::find_local_by_path(module_path)
        } else {
            Self::_find_remote_by_path(module_path, process)
        }
    }

    /// Searches for a module with the given name or path in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local(
        module_name_or_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        Self::find(module_name_or_path, P::current())
    }

    /// Searches for a module with the given name in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_name(
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        Self::find_local_by_name_or_abs_path(module_name.as_ref())
    }

    /// Searches for a module with the given path in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_path(
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        let absolute_path = module_path.as_ref().absolutize()?;
        Self::find_local_by_name_or_abs_path(absolute_path.as_ref())
    }

    pub(crate) fn find_local_by_name_or_abs_path(
        module: &Path,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        let module = U16CString::from_os_str(module.as_os_str())?;
        Self::find_local_by_name_or_abs_path_wstr(&module)
    }

    pub(crate) fn find_local_by_name_or_abs_path_wstr(
        module: &U16CStr,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
        if handle.is_null() {
            let err = io::Error::last_os_error();
            if err.raw_os_error().unwrap() == ERROR_MOD_NOT_FOUND as _ {
                return Ok(None);
            }

            return Err(err.into());
        }

        Ok(Some(unsafe { Self::new_local_unchecked(handle) }))
    }

    fn _find_remote_by_name(
        module_name: impl AsRef<Path>,
        process: P,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        assert!(!process.is_current());

        process
            .find_module_by_name(module_name)
            .map_err(|e| e.into())
    }

    fn _find_remote_by_path(
        module_path: impl AsRef<Path>,
        process: P,
    ) -> Result<Option<ProcessModule<P>>, IoOrNulError> {
        assert!(!process.is_current());

        process
            .find_module_by_path(module_path)
            .map_err(|e| e.into())
    }

    /// Returns the underlying handle og the module.
    #[must_use]
    pub fn handle(&self) -> ModuleHandle {
        self.handle.as_ptr()
    }

    /// Returns the process this module is loaded in.
    #[must_use]
    pub fn process(&self) -> &P {
        &self.process
    }

    /// Returns a value indicating whether the module is loaded in current process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }
    /// Returns a value indicating whether the module is loaded in a remote process (not the current one).
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    /// Returns the path that the module was loaded from.
    pub fn path(&self) -> Result<PathBuf, io::Error> {
        if self.is_local() {
            win_fill_path_buf_helper(|buf_ptr, buf_size| {
                let buf_size = buf_size as u32;
                let result = unsafe { GetModuleFileNameW(self.handle(), buf_ptr, buf_size) };
                if result == 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                        FillPathBufResult::BufTooSmall { size_hint: None }
                    } else {
                        FillPathBufResult::Error(err)
                    }
                } else if result >= buf_size {
                    FillPathBufResult::BufTooSmall { size_hint: None }
                } else {
                    FillPathBufResult::Success {
                        actual_len: result as usize,
                    }
                }
            })
        } else {
            win_fill_path_buf_helper(|buf_ptr, buf_size| {
                let buf_size = buf_size as u32;
                let result = unsafe {
                    GetModuleFileNameExW(
                        self.process().as_raw_handle(),
                        self.handle(),
                        buf_ptr,
                        buf_size,
                    )
                };
                if result == 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                        FillPathBufResult::BufTooSmall { size_hint: None }
                    } else {
                        FillPathBufResult::Error(err)
                    }
                } else if result >= buf_size {
                    FillPathBufResult::BufTooSmall { size_hint: None }
                } else {
                    FillPathBufResult::Success {
                        actual_len: result as usize,
                    }
                }
            })
        }
    }

    /// Returns the base name of the file the module was loaded from.
    pub fn base_name(&self) -> Result<OsString, io::Error> {
        if self.is_local() {
            self.path().map(|path| path.file_name().unwrap().to_owned())
        } else {
            win_fill_path_buf_helper(|buf_ptr, buf_size| {
                let buf_size = buf_size as u32;
                let result = unsafe {
                    GetModuleBaseNameW(
                        self.process().as_raw_handle(),
                        self.handle(),
                        buf_ptr,
                        buf_size,
                    )
                };
                if result == 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                        FillPathBufResult::BufTooSmall { size_hint: None }
                    } else {
                        FillPathBufResult::Error(err)
                    }
                } else if result >= buf_size {
                    FillPathBufResult::BufTooSmall { size_hint: None }
                } else {
                    FillPathBufResult::Success {
                        actual_len: result as usize,
                    }
                }
            })
            .map(|e| e.into())
        }
    }

    /// Returns a pointer to the procedure with the given name from this module.
    ///
    /// # Note
    /// This function is only supported for modules in the current process.
    pub fn get_local_procedure_address(
        &self,
        proc_name: impl AsRef<str>,
    ) -> Result<FARPROC, GetLocalProcedureAddressError> {
        if self.is_remote() {
            return Err(GetLocalProcedureAddressError::UnsupportedRemoteTarget);
        }

        self.get_local_procedure_address_cstr(&CString::new(proc_name.as_ref())?)
            .map_err(|e| e.into())
    }

    pub(crate) fn get_local_procedure_address_cstr(
        &self,
        proc_name: &CStr,
    ) -> Result<FARPROC, io::Error> {
        assert!(self.is_local());

        let fn_ptr = unsafe { GetProcAddress(self.handle(), proc_name.as_ptr()) };
        if fn_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(fn_ptr)
    }
}

impl BorrowedProcessModule<'_> {
    /// Tries to create a new [`OwnedProcessModule`] instance for this process module.
    pub fn try_to_owned(&self) -> Result<OwnedProcessModule, io::Error> {
        self.process
            .try_to_owned()
            .map(|process| OwnedProcessModule {
                process,
                handle: self.handle,
            })
    }
}

impl TryFrom<BorrowedProcessModule<'_>> for OwnedProcessModule {
    type Error = io::Error;

    fn try_from(module: BorrowedProcessModule<'_>) -> Result<Self, Self::Error> {
        module.try_to_owned()
    }
}

impl<'a> From<&'a OwnedProcessModule> for BorrowedProcessModule<'a> {
    fn from(module: &'a OwnedProcessModule) -> Self {
        module.borrowed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_local_by_name_present() {
        let result = BorrowedProcessModule::find_local_by_name("kernel32.dll");
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().is_some());

        let module = result.unwrap().unwrap();
        assert!(module.is_local());
        assert!(!module.handle().is_null());
    }

    #[test]
    fn find_local_by_name_absent() {
        let result = BorrowedProcessModule::find_local_by_name("kernel33.dll");
        assert!(&result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
