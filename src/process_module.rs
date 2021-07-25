use std::{
    convert::TryInto,
    error::Error,
    ffi::{CStr, OsString},
    path::{Path, PathBuf},
};

use crate::{utils::WinPathBuf, Process};
use path_absolutize::Absolutize;
use rust_win32error::Win32Error;
use widestring::U16CString;
use winapi::{shared::{minwindef::{HMODULE, MAX_PATH, __some_function}, winerror::ERROR_MOD_NOT_FOUND}, um::{
        libloaderapi::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
        psapi::{GetModuleBaseNameW, GetModuleFileNameExW},
    }};

/// A handle to a process module.
/// Note that this is not a `HANDLE` in windows terms but the base address of a loaded module.
pub type ModuleHandle = HMODULE;

/// A loaded module of a process. This module may or may not be of the current process.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcessModule<'a> {
    handle: ModuleHandle,
    process: Option<&'a Process>,
}

impl<'a> ProcessModule<'a> {
    /// Contructs a new instance from the given handle and optionaly the process to which the module belongs.
    /// If the module is from the current process [`None`] can be specified.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that the module is loaded into the given process
    ///  (and stays that way while interacting).
    pub unsafe fn new(handle: ModuleHandle, mut process: Option<&'a Process>) -> Self {
        if process.is_some() && process.unwrap().is_current() {
            process = None
        }
        Self { handle, process }
    }
    /// Contructs a new instance from the given module handle of the current process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that it is loaded into the current process
    ///  (and stays that way while interacting).
    pub unsafe fn new_local(handle: ModuleHandle) -> Self {
        unsafe { Self::new(handle, None) }
    }
    /// Contructs a new instance from the given module handle of the given remote process.
    ///
    /// # Safety
    /// The caller must guarantee that the given handle is valid and that it is loaded into the given process
    ///  (and stays that way while interacting).
    pub unsafe fn new_remote(handle: ModuleHandle, process: &'a Process) -> Self {
        unsafe { Self::new(handle, Some(process)) }
    }

    /// Searches for a module with the given name or path in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn get(
        module_name_or_path: impl AsRef<Path>,
        process: Option<&'a Process>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let module_name_or_path = module_name_or_path.as_ref();
        if module_name_or_path.has_root() {
            Self::from_path(module_name_or_path, process)
        } else {
            Self::from_name(module_name_or_path, process)
        }
    }
    /// Searches for a module with the given name in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn from_name(
        module_name: impl AsRef<Path>,
        process: Option<&'a Process>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        if let Some(process) = process {
            Self::get_remote_from_name(module_name, process)
        } else {
            Self::get_local_from_name(module_name)
        }
    }
    /// Searches for a module with the given path in the given process (the current one if [`None`] was specified).
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn from_path(
        module_path: impl AsRef<Path>,
        process: Option<&'a Process>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        if let Some(process) = process {
            Self::get_remote_from_path(module_path, process)
        } else {
            Self::get_local_from_path(module_path)
        }
    }

    pub fn get_local(
        module_name_or_path: impl AsRef<Path>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        Self::get(module_name_or_path, None)
    }
    pub fn get_local_from_name(
        module_name: impl AsRef<Path>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        Self::_get_local_from_name_or_path(module_name)
    }
    pub fn get_local_from_path(
        module_path: impl AsRef<Path>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let absolute_path = module_path.as_ref().absolutize()?;
        Self::_get_local_from_name_or_path(absolute_path)
    }
    fn _get_local_from_name_or_path(
        module: impl AsRef<Path>,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let wide_string = U16CString::from_os_str(module.as_ref().as_os_str())?;

        let handle = unsafe { GetModuleHandleW(wide_string.as_ptr()) };
        if handle.is_null() {
            let err = Win32Error::new();
            if err.get_error_code() == ERROR_MOD_NOT_FOUND {
                return Ok(None);
            }

            return Err(err.into());
        }

        // TODO:
        Ok(Some(unsafe { Self::new_local(handle) }))
    }

    pub fn get_remote(
        module_name_or_path: impl AsRef<Path>,
        process: &'a Process,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        Self::get(module_name_or_path, Some(process))
    }
    pub fn get_remote_from_path(
        module_path: impl AsRef<Path>,
        process: &'a Process,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        if process.is_current() {
            Self::get_local_from_path(module_path)
        } else {
            process.find_module_by_path(module_path)
        }
    }
    pub fn get_remote_from_name(
        module_name: impl AsRef<Path>,
        process: &'a Process,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        if process.is_current() {
            Self::get_local_from_name(module_name)
        } else {
            process
                .find_module_by_name(module_name)
                .map_err(|e| e.into()) // TODO:
        }
    }

    pub fn handle(&self) -> ModuleHandle {
        self.handle
    }
    pub fn process(&self) -> Option<&'a Process> {
        self.process
    }

    pub fn is_local(&self) -> bool {
        self.process.is_none()
    }
    pub fn is_remote(&self) -> bool {
        !self.is_local()
    }

    pub fn get_path(&self) -> Result<PathBuf, Win32Error> {
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
            return Err(dbg!(Win32Error::new()));
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
                self.process.unwrap().handle(),
                self.handle(),
                module_path_buf.as_mut_ptr(),
                module_path_buf_size,
            )
        };
        if result == 0 {
            return Err(dbg!(Win32Error::new()));
        }

        let module_path_len = result as usize;
        let module_path = unsafe { module_path_buf.assume_init_path_buf(module_path_len) };
        Ok(module_path)
    }

    pub fn get_base_name(&self) -> Result<OsString, Win32Error> {
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
                self.process.unwrap().handle(),
                self.handle(),
                module_name_buf.as_mut_ptr(),
                module_name_buf_size,
            )
        };
        if result == 0 {
            return Err(dbg!(Win32Error::new()));
        }

        let module_name_len = result as usize;
        let module_name = unsafe { module_name_buf.assume_init_os_string(module_name_len) };
        Ok(module_name)
    }

    pub fn get_proc(
        &self,
        proc_name: impl AsRef<CStr>,
    ) -> Result<*const __some_function, Box<dyn Error>> {
        if self.is_remote() {
            // TODO: proper error handling
            return Err("Not supported".into());
        }

        let fn_ptr = unsafe { GetProcAddress(self.handle(), proc_name.as_ref().as_ptr()) };
        if fn_ptr.is_null() {
            return Err(Win32Error::new().into());
        }
        Ok(fn_ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_local_by_name_present() {
        let result = ProcessModule::get_local_from_name("kernel32.dll");
        assert!(result.is_ok());
        assert!(result.as_ref().unwrap().is_some());

        let module = result.unwrap().unwrap();
        assert!(module.is_local());
        assert!(!module.handle().is_null());
    }

    #[test]
    fn find_local_by_name_absent() {
        let result = ProcessModule::get_local_from_name("kernel33.dll");
        assert!(dbg!(&result).is_ok());
        assert!(result.unwrap().is_none());
    }
}
