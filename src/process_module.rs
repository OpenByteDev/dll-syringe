use std::{
    convert::TryInto,
    ffi::{CStr, CString, OsString},
    path::{Path, PathBuf},
};

use crate::{
    error::{FindModuleByPathError, GetLocalProcedureError, Win32OrNulError},
    utils::WinPathBuf,
    ProcessRef,
};
use path_absolutize::Absolutize;
use rust_win32error::Win32Error;
use widestring::{U16CStr, U16CString};
use winapi::{
    shared::{
        minwindef::{__some_function, HMODULE},
        winerror::ERROR_MOD_NOT_FOUND,
    },
    um::{
        libloaderapi::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW},
    },
};

/// A handle to a process module.
///
/// # Note
/// This is not a `HANDLE` but a [`HMODULE`](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types#HMODULE) which is the base address of a loaded module.
pub type ModuleHandle = HMODULE;

/// A loaded module of a running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessModule<'a> {
    handle: ModuleHandle,
    process: ProcessRef<'a>,
}

impl<'a> ProcessModule<'a> {
    /// Contructs a new instance from the given module handle and its corresponding process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process. (and stays that way while interacting).
    pub const unsafe fn new(handle: ModuleHandle, process: ProcessRef<'a>) -> Self {
        Self { handle, process }
    }
    /// Contructs a new instance from the given module handle loaded in the current process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that it is loaded into the current process. (and stays that way while interacting).
    pub unsafe fn new_local(handle: ModuleHandle) -> Self {
        unsafe { Self::new(handle, ProcessRef::current()) }
    }

    /// Searches for a module with the given name or path in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find(
        module_name_or_path: impl AsRef<Path>,
        process: ProcessRef<'a>,
    ) -> Result<Option<Self>, FindModuleByPathError> {
        let module_name_or_path = module_name_or_path.as_ref();
        if module_name_or_path.has_root() {
            Self::find_by_path(module_name_or_path, process)
        } else {
            Self::find_by_name(module_name_or_path, process).map_err(|e| e.into())
        }
    }
    /// Searches for a module with the given name in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_name(
        module_name: impl AsRef<Path>,
        process: ProcessRef<'a>,
    ) -> Result<Option<Self>, Win32OrNulError> {
        if process.is_current() {
            Self::find_local_by_name(module_name)
        } else {
            Self::_find_remote_by_name(module_name, process)
        }
    }
    /// Searches for a module with the given path in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_by_path(
        module_path: impl AsRef<Path>,
        process: ProcessRef<'a>,
    ) -> Result<Option<Self>, FindModuleByPathError> {
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
    ) -> Result<Option<Self>, FindModuleByPathError> {
        Self::find(module_name_or_path, ProcessRef::current())
    }
    /// Searches for a module with the given name in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_name(
        module_name: impl AsRef<Path>,
    ) -> Result<Option<Self>, Win32OrNulError> {
        Self::_find_local_by_name_or_abs_path(module_name)
    }
    /// Searches for a module with the given path in the current process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn find_local_by_path(
        module_path: impl AsRef<Path>,
    ) -> Result<Option<Self>, FindModuleByPathError> {
        let absolute_path = module_path.as_ref().absolutize()?;
        Self::_find_local_by_name_or_abs_path(absolute_path).map_err(|e| e.into())
    }
    pub(crate) fn _find_local_by_name_or_abs_path(
        module: impl AsRef<Path>,
    ) -> Result<Option<Self>, Win32OrNulError> {
        let wide_string = U16CString::from_os_str(module.as_ref().as_os_str())?;
        Self::__find_local_by_name_or_abs_path(&wide_string)
    }
    pub(crate) fn __find_local_by_name_or_abs_path(
        module: &U16CStr,
    ) -> Result<Option<Self>, Win32OrNulError> {
        let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
        if handle.is_null() {
            let err = Win32Error::new();
            if err.get_error_code() == ERROR_MOD_NOT_FOUND {
                return Ok(None);
            }

            return Err(err.into());
        }

        Ok(Some(unsafe { Self::new_local(handle) }))
    }

    /// Searches for a module with the given name in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn _find_remote_by_name(
        module_name: impl AsRef<Path>,
        process: ProcessRef<'a>,
    ) -> Result<Option<ProcessModule<'a>>, Win32OrNulError> {
        assert!(!process.is_current());

        process
            .find_module_by_name(module_name)
            .map_err(|e| e.into())
    }
    /// Searches for a module with the given path in the given process.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn _find_remote_by_path(
        module_path: impl AsRef<Path>,
        process: ProcessRef<'a>,
    ) -> Result<Option<Self>, FindModuleByPathError> {
        assert!(!process.is_current());

        process
            .find_module_by_path(module_path)
            .map_err(|e| e.into())
    }

    /// Gets the underlying handle to the module.
    #[must_use]
    pub const fn handle(&self) -> ModuleHandle {
        self.handle
    }
    /// Gets the process this module belongs to.
    #[must_use]
    pub const fn process(&self) -> ProcessRef<'_> {
        self.process
    }

    /// Gets a value indicating whether the module is from the current process.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.process().is_current()
    }
    /// Gets a value indicating whether the module is from a remote process (not from the current one).
    #[must_use]
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    /// Gets the path that the module was loaded from.
    pub fn path(&self) -> Result<PathBuf, Win32Error> {
        if self.is_local() {
            self._get_path_of_local()
        } else {
            self._get_path_of_remote()
        }
    }
    fn _get_path_of_local(&self) -> Result<PathBuf, Win32Error> {
        assert!(self.is_local());

        let mut module_path_buf = WinPathBuf::new();
        let module_path_buf_size: u32 = module_path_buf.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameW(
                self.handle(),
                module_path_buf.as_mut_ptr(),
                module_path_buf_size,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let module_path_len = result as usize;
        let module_path = unsafe { module_path_buf.assume_init_path_buf(module_path_len) };
        Ok(module_path)
    }
    fn _get_path_of_remote(&self) -> Result<PathBuf, Win32Error> {
        assert!(self.is_remote());

        let mut module_path_buf = WinPathBuf::new();
        let module_path_buf_size: u32 = module_path_buf.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameExW(
                self.process.handle(),
                self.handle(),
                module_path_buf.as_mut_ptr(),
                module_path_buf_size,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let module_path_len = result as usize;
        let module_path = unsafe { module_path_buf.assume_init_path_buf(module_path_len) };
        Ok(module_path)
    }

    /// Gets the base name (= file name) of the module.
    pub fn base_name(&self) -> Result<OsString, Win32Error> {
        if self.is_local() {
            self._get_base_name_of_local()
        } else {
            self._get_base_name_of_remote()
        }
    }
    fn _get_base_name_of_local(&self) -> Result<OsString, Win32Error> {
        assert!(self.is_local());

        self._get_path_of_local()
            .map(|path| path.file_name().unwrap().to_owned())
    }
    fn _get_base_name_of_remote(&self) -> Result<OsString, Win32Error> {
        assert!(self.is_remote());

        let mut module_name_buf = WinPathBuf::new();
        let module_name_buf_size: u32 = module_name_buf.len().try_into().unwrap();
        let result = unsafe {
            GetModuleBaseNameW(
                self.process.handle(),
                self.handle(),
                module_name_buf.as_mut_ptr(),
                module_name_buf_size,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let module_name_len = result as usize;
        let module_name = unsafe { module_name_buf.assume_init_os_string(module_name_len) };
        Ok(module_name)
    }

    /// Gets a pointer to the procedure with the given name from the module.
    ///
    /// # Note
    /// This function is only supported for modules in the current process.
    pub fn get_local_procedure(
        &self,
        proc_name: impl AsRef<str>,
    ) -> Result<*const __some_function, GetLocalProcedureError> {
        if self.is_remote() {
            return Err(GetLocalProcedureError::UnsupportedRemoteTarget);
        }

        self.__get_local_procedure(&CString::new(proc_name.as_ref())?)
            .map_err(|e| e.into())
    }

    pub(crate) fn __get_local_procedure(
        &self,
        proc_name: &CStr,
    ) -> Result<*const __some_function, Win32Error> {
        assert!(self.is_local());

        let fn_ptr = unsafe { GetProcAddress(self.handle(), proc_name.as_ptr()) };
        if fn_ptr.is_null() {
            return Err(Win32Error::new());
        }
        Ok(fn_ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_local_by_name_present() {
        let result = ProcessModule::find_local_by_name("kernel32.dll");
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().is_some());

        let module = result.unwrap().unwrap();
        assert!(module.is_local());
        assert!(!module.handle().is_null());
    }

    #[test]
    fn find_local_by_name_absent() {
        let result = ProcessModule::find_local_by_name("kernel33.dll");
        assert!(&result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
