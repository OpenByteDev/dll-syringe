use std::{
    cmp,
    convert::TryInto,
    error::Error,
    ffi::OsString,
    mem::{self, MaybeUninit},
    os::windows::prelude::IntoRawHandle,
    path::{Path, PathBuf},
    process::Child,
};

use rust_win32error::Win32Error;
use sysinfo::{ProcessExt, SystemExt};
use widestring::U16Str;
use winapi::{
    shared::minwindef::{FALSE, HMODULE, MAX_PATH},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{GetCurrentProcess, OpenProcess, TerminateProcess},
        psapi::{EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL},
        winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
        wow64apiset::IsWow64Process,
    },
};

use crate::{ArrayOrVecSlice, Module};

pub type ProcessHandle = *mut winapi::ctypes::c_void;

#[derive(Debug, PartialEq, Eq)]
pub struct Process {
    handle: ProcessHandle,
    owns_handle: bool,
}

// Creation and Destruction
impl Process {
    /// Creates a new instance from the given raw handle.
    ///
    /// # Safety
    /// - The given handle needs to be a valid process handle.
    /// - If `owns_handle` is `true` the given handle needs to have been owned by the caller and it has to be valid to close the handle.
    /// - The caller is not allowed to close the given handle.
    /// - If `owns_handle` is `false` the handle has to be valid for the lifetime of the created instance.
    /// - The handle needs to have the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
    ///     - PROCESS_CREATE_THREAD
    ///     - PROCESS_QUERY_INFORMATION
    ///     - PROCESS_VM_OPERATION
    ///     - PROCESS_VM_WRITE
    ///     - PROCESS_VM_READ
    pub unsafe fn from_handle(handle: ProcessHandle, owns_handle: bool) -> Self {
        Self {
            handle,
            owns_handle,
        }
    }

    pub fn from_pid(pid: u32) -> Result<Self, Win32Error> {
        let handle = unsafe {
            OpenProcess(
                // access required for performing dll injection
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_READ,
                FALSE,
                pid,
            )
        };

        if handle.is_null() {
            return Err(Win32Error::new());
        }

        Ok(unsafe { Self::from_handle(handle, true) })
    }

    pub fn find_all_by_name(name: impl AsRef<str>) -> Vec<Self> {
        // TODO: avoid using sysinfo just for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system
            .processes()
            .values()
            .filter(move |process| process.name().contains(name.as_ref()))
            .map(|process| process.pid())
            .filter_map(|pid| Process::from_pid(pid as _).ok())
            .collect()
    }

    pub fn find_first_by_name(name: impl AsRef<str>) -> Option<Self> {
        // TODO: avoid using sysinfo just for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system
            .processes()
            .values()
            .filter(move |process| process.name().contains(name.as_ref()))
            .map(|process| process.pid())
            .filter_map(|pid| Process::from_pid(pid as _).ok())
            .next()
    }

    pub fn from_child(child: Child) -> Self {
        let handle = child.into_raw_handle();
        unsafe { Self::from_handle(handle as *mut _, true) }
    }

    pub fn current() -> Self {
        let handle = unsafe { GetCurrentProcess() };

        // the handle is only a pseudo handle representing the current process which does not need to be closed.
        unsafe { Self::from_handle(handle, false) }
    }

    pub fn handle(&self) -> ProcessHandle {
        self.handle
    }

    pub fn into_handle(mut self) -> (ProcessHandle, bool) {
        let did_own_handle = self.owns_handle;

        // mark as non-owning to avoid closing the handle
        self.owns_handle = false;

        (self.handle, did_own_handle)
    }

    pub fn close(mut self) -> Result<(), (Win32Error, Self)> {
        self._close().map_err(|error| (error, self))
    }

    fn _close(&mut self) -> Result<(), Win32Error> {
        if self.owns_handle {
            let result = unsafe { CloseHandle(self.handle) };

            if result != 0 {
                return Err(Win32Error::new());
            }
        }

        Ok(())
    }
}

impl Process {
    pub fn get_modules(&self) -> Result<impl AsRef<[Module]>, Win32Error> {
        let mut module_buf = MaybeUninit::uninit_array::<1024>();
        let mut module_buf_byte_size = mem::size_of::<HMODULE>() * module_buf.len();
        let mut bytes_needed_target = MaybeUninit::uninit();
        let result = unsafe {
            EnumProcessModulesEx(
                self.handle,
                module_buf[0].as_mut_ptr(),
                module_buf_byte_size.try_into().unwrap(),
                bytes_needed_target.as_mut_ptr(),
                LIST_MODULES_ALL,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let mut bytes_needed = unsafe { bytes_needed_target.assume_init() } as usize;

        let mut module_buf_vec: Vec<_>;
        let modules = if bytes_needed <= module_buf_byte_size {
            // buffer size was sufficient
            let module_buf_len = bytes_needed / mem::size_of::<HMODULE>();
            let module_buf = unsafe {
                mem::transmute::<[MaybeUninit<HMODULE>; 1024], [Module; 1024]>(module_buf)
            };
            ArrayOrVecSlice::from_array(module_buf, 0..module_buf_len)
        } else {
            // buffer size was not sufficient
            module_buf_vec = Vec::new();

            // we loop here trying to find a buffer size that fits all handles
            // this needs to be a loop as the returned bytes_needed seems to be more of an estimate and sometimes
            // more than 1 iteration is necessary. We try to avoid to many iterations by always choosing a buffer at least twice
            // the previous size.
            loop {
                module_buf_byte_size = cmp::max(bytes_needed, module_buf_byte_size * 2);
                let module_buf_len = module_buf_byte_size / mem::size_of::<HMODULE>();
                module_buf_vec.resize_with(module_buf_len, MaybeUninit::uninit);

                bytes_needed_target = MaybeUninit::uninit();
                let result = unsafe {
                    EnumProcessModulesEx(
                        self.handle,
                        module_buf_vec[0].as_mut_ptr(),
                        module_buf_byte_size.try_into().unwrap(),
                        bytes_needed_target.as_mut_ptr(),
                        LIST_MODULES_ALL,
                    )
                };
                if result == 0 {
                    return Err(Win32Error::new());
                }
                bytes_needed = unsafe { bytes_needed_target.assume_init() } as usize;

                if bytes_needed <= module_buf_byte_size {
                    let module_buf_len = bytes_needed / mem::size_of::<HMODULE>();
                    let module_buf_vec = unsafe {
                        mem::transmute::<Vec<MaybeUninit<HMODULE>>, Vec<Module>>(module_buf_vec)
                    };
                    break ArrayOrVecSlice::from_vec(module_buf_vec, 0..module_buf_len);
                }
            }
        };

        Ok(modules)
    }

    pub fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<Module>, Win32Error> {
        let target_module_name = module_name.as_ref().as_os_str();
        let modules = self.get_modules()?;

        for module in modules.as_ref() {
            let module_name = self.get_module_name(module)?;

            if module_name.eq_ignore_ascii_case(target_module_name) {
                return Ok(Some(*module));
            }
        }

        Ok(None)
    }

    pub fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<Module>, Box<dyn Error>> {
        let target_module_name = module_path.as_ref().as_os_str();
        let modules = self.get_modules()?;

        for module in modules.as_ref() {
            let module_path = self.get_module_path(module)?;

            if module_path
                .as_os_str()
                .eq_ignore_ascii_case(target_module_name)
            {
                return Ok(Some(*module));
            }
        }

        Ok(None)
    }

    pub fn is_wow64(&self) -> Result<bool, Win32Error> {
        let mut is_wow64 = MaybeUninit::uninit();
        let result = unsafe { IsWow64Process(self.handle, is_wow64.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::new());
        }
        Ok(unsafe { is_wow64.assume_init() } != FALSE)
    }

    pub fn get_module_path(&self, module: &Module) -> Result<PathBuf, Win32Error> {
        let mut module_name = MaybeUninit::uninit_array::<MAX_PATH>();
        let module_name_len: u32 = module_name.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameExW(
                self.handle(),
                module.handle(),
                module_name[0].as_mut_ptr(),
                module_name_len,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let module_name_len = result as usize;
        let module_name = &module_name[..module_name_len];
        let module_name = unsafe { mem::transmute::<&[MaybeUninit<u16>], &[u16]>(module_name) };
        Ok(U16Str::from_slice(module_name).to_os_string().into())
    }

    pub fn get_module_name(&self, module: &Module) -> Result<OsString, Win32Error> {
        let mut module_name = MaybeUninit::uninit_array::<MAX_PATH>();
        let module_name_len: u32 = module_name.len().try_into().unwrap();
        let result = unsafe {
            GetModuleBaseNameW(
                self.handle(),
                module.handle(),
                module_name[0].as_mut_ptr(),
                module_name_len,
            )
        };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let module_name_len = result as usize;
        let module_name = &module_name[..module_name_len];
        let module_name = unsafe { mem::transmute::<&[MaybeUninit<u16>], &[u16]>(module_name) };
        Ok(U16Str::from_slice(module_name).to_os_string())
    }

    pub fn kill(self) -> Result<(), Win32Error> {
        self.kill_with_exit_code(1)
    }

    pub fn kill_with_exit_code(self, exit_code: u32) -> Result<(), Win32Error> {
        let result = unsafe { TerminateProcess(self.handle(), exit_code) };
        if result == 0 {
            return Err(Win32Error::new());
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self._close();
    }
}

impl From<Process> for ProcessHandle {
    fn from(process: Process) -> Self {
        process.handle()
    }
}

impl From<Child> for Process {
    fn from(child: Child) -> Self {
        Self::from_child(child)
    }
}
