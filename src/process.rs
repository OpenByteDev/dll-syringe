use std::{borrow::Cow, cmp, convert::TryInto, error::Error, ffi::OsStr, mem::{self, MaybeUninit}, os::windows::prelude::IntoRawHandle, path::Path, process::Child};

use rust_win32error::Win32Error;
use sysinfo::{ProcessExt, SystemExt};
use winapi::{
    shared::minwindef::{FALSE, HMODULE},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{GetCurrentProcess, OpenProcess, TerminateProcess},
        psapi::{EnumProcessModulesEx, LIST_MODULES_ALL},
        winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
        wow64apiset::IsWow64Process,
    },
};

use crate::{ArrayOrVecSlice, ModuleHandle, ProcessModule};

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

    pub fn current_handle() -> ProcessHandle {
        unsafe { GetCurrentProcess() }
    }

    pub fn current() -> Self {
        // the handle is only a pseudo handle representing the current process which does not need to be closed.
        unsafe { Self::from_handle(Self::current_handle(), false) }
    }

    pub fn is_current(&self) -> bool {
        self.handle() == Self::current_handle()
    }

    pub fn handle(&self) -> ProcessHandle {
        self.handle
    }

    pub fn owns_handle(&self) -> bool {
        self.owns_handle
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
        if self.owns_handle() {
            let result = unsafe { CloseHandle(self.handle) };

            if result != 0 {
                return Err(Win32Error::new());
            }
        }

        Ok(())
    }
}

impl Process {
    pub fn get_module_handles(&self) -> Result<impl AsRef<[ModuleHandle]>, Win32Error> {
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
                mem::transmute::<[MaybeUninit<HMODULE>; 1024], [ModuleHandle; 1024]>(module_buf)
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
                        mem::transmute::<Vec<MaybeUninit<HMODULE>>, Vec<ModuleHandle>>(
                            module_buf_vec,
                        )
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
    ) -> Result<Option<ProcessModule>, Win32Error> {
        let target_module_name =  module_name.as_ref();

        // add default file extension if missing
        let target_module_name = if target_module_name.extension().is_some() {
            Cow::Owned(target_module_name.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_name.as_os_str())
        };

        let modules = self.get_module_handles()?;

        for &module_handle in modules.as_ref() {
            let module = unsafe { ProcessModule::new_remote(module_handle, self) };
            let module_name = module.get_base_name()?;

            if module_name.eq_ignore_ascii_case(&target_module_name) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    pub fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule>, Box<dyn Error>> {
        let target_module_path = module_path.as_ref();

        // add default file extension if missing
        let target_module_path = if target_module_path.extension().is_some() {
            Cow::Owned(target_module_path.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_path.as_os_str())
        };

        let modules = self.get_module_handles()?;

        for &module_handle in modules.as_ref() {
            let module = unsafe { ProcessModule::new_remote(module_handle, self) };
            let module_path = module.get_path()?.into_os_string();

            if module_path.eq_ignore_ascii_case(&target_module_path) {
                return Ok(Some(module));
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
