use std::{
    convert::TryInto,
    error::Error,
    ffi::CStr,
    mem::{self, MaybeUninit},
    path::{Path, PathBuf},
};

use path_absolutize::Absolutize;
use rust_win32error::Win32Error;
use widestring::{U16CStr, U16CString, U16Str};
use winapi::{
    shared::minwindef::{__some_function, HMODULE, MAX_PATH},
    um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress},
};

pub type ModuleHandle = HMODULE;

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Module {
    handle: ModuleHandle,
}

impl Module {
    pub fn new(handle: ModuleHandle) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> ModuleHandle {
        self.handle
    }

    pub fn from_name_or_path(module: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let module_path = module.as_ref();
        if module_path.has_root() {
            Self::from_path(module)
        } else {
            Self::from_name(U16CString::from_os_str(module_path.as_os_str())?)
        }
    }

    pub fn from_path(module_path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let absolute_path = module_path.as_ref().absolutize()?;
        let wide_path = U16CString::from_os_str(absolute_path.as_os_str())?;
        Self::from_name(wide_path)
    }

    pub fn from_name(module_name: impl AsRef<U16CStr>) -> Result<Self, Box<dyn Error>> {
        let handle = unsafe { GetModuleHandleW(module_name.as_ref().as_ptr()) };
        if handle.is_null() {
            return Err(Win32Error::new().into());
        }
        Ok(Self::new(handle))
    }

    pub fn get_path(&self) -> Result<PathBuf, Win32Error> {
        let mut module_name = MaybeUninit::uninit_array::<MAX_PATH>();
        let module_name_len: u32 = module_name.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameW(self.handle(), module_name[0].as_mut_ptr(), module_name_len)
        };
        if result == 0 {
            return Err(dbg!(Win32Error::new()));
        }

        let module_name_len = result as usize;
        let module_name = &module_name[..module_name_len];
        let module_name = unsafe { mem::transmute::<&[MaybeUninit<u16>], &[u16]>(module_name) };
        Ok(U16Str::from_slice(module_name).to_os_string().into())
    }

    pub fn get_proc_local(
        &self,
        proc_name: impl AsRef<CStr>,
    ) -> Result<*const __some_function, Win32Error> {
        let fn_ptr = unsafe { GetProcAddress(self.handle(), proc_name.as_ref().as_ptr()) };
        if fn_ptr.is_null() {
            return Err(Win32Error::new());
        }
        Ok(fn_ptr)
    }
}

impl From<Module> for ModuleHandle {
    fn from(module: Module) -> Self {
        module.handle()
    }
}

impl From<ModuleHandle> for Module {
    fn from(module_handle: ModuleHandle) -> Self {
        Self::new(module_handle)
    }
}
