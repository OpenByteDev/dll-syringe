use std::{
    borrow::Cow,
    cmp,
    convert::TryInto,
    ffi::c_void,
    hash::{Hash, Hasher},
    mem::{self, MaybeUninit},
    num::NonZeroU32,
    os::windows::{
        prelude::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
        raw::HANDLE,
    },
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};

use get_last_error::Win32Error;
use winapi::{
    shared::{
        minwindef::{FALSE, HMODULE},
        winerror::ERROR_CALL_NOT_IMPLEMENTED,
    },
    um::{
        handleapi::DuplicateHandle,
        libloaderapi::GetModuleFileNameW,
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread,
            GetProcessId, TerminateProcess,
        },
        psapi::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_FAILED},
        winnt::DUPLICATE_SAME_ACCESS,
        wow64apiset::{GetSystemWow64DirectoryA, IsWow64Process},
    },
};

use crate::{
    utils::{retry_with_filter, ArrayOrVecSlice, UninitArrayBuf, WinPathBuf},
    ModuleHandle, Process, ProcessHandle, ProcessModule,
};

/// A struct representing a running process (including the current one).
/// This struct does NOT own the underlying process handle.
///
/// # Note
/// The underlying handle has to have the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessRef<'a>(BorrowedHandle<'a>);

impl AsRawHandle for ProcessRef<'_> {
    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

impl AsHandle for ProcessRef<'_> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl<'a, 'b> PartialEq<ProcessRef<'a>> for ProcessRef<'b> {
    fn eq(&self, other: &ProcessRef<'a>) -> bool {
        // TODO: (unsafe { CompareObjectHandles(self.handle(), other.handle()) }) != FALSE

        self.handle() == other.handle()
            || self.pid().map_or(0, |v| v.get()) == other.pid().map_or(0, |v| v.get())
    }
}

impl PartialEq<Process> for ProcessRef<'_> {
    fn eq(&self, other: &Process) -> bool {
        self == &other.get_ref()
    }
}

impl PartialEq<ProcessRef<'_>> for Process {
    fn eq(&self, other: &ProcessRef<'_>) -> bool {
        &self.get_ref() == other
    }
}

impl Eq for ProcessRef<'_> {}

impl Hash for ProcessRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle().hash(state);
    }
}

impl<'a> From<&'a Process> for ProcessRef<'a> {
    fn from(process: &'a Process) -> Self {
        process.get_ref()
    }
}

impl<'a> ProcessRef<'a> {
    /// Creates a new instance from a borrowed handle.
    ///
    /// # Safety
    /// The handle needs to fulfill the priviliges listed in the [struct documentation](ProcessRef).
    #[must_use]
    pub const unsafe fn borrow_from_handle(handle: BorrowedHandle<'a>) -> Self {
        Self(handle)
    }

    /// Returns the raw pseudo handle representing the current process.
    #[must_use]
    pub fn raw_current_handle() -> ProcessHandle {
        unsafe { GetCurrentProcess() }
    }

    /// Returns the pseudo handle representing the current process.
    #[must_use]
    pub fn current_handle() -> BorrowedHandle<'static> {
        // the handle is only a pseudo handle representing the current process which does not need to be closed.
        unsafe { BorrowedHandle::borrow_raw_handle(Self::raw_current_handle()) }
    }

    /// Returns an instance representing the current process.
    #[must_use]
    pub fn current() -> Self {
        Self(Self::current_handle())
    }

    /// Returns whether this instance represents the current process.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self == &ProcessRef::current()
    }

    /// Returns whether this process is still alive and running.
    ///
    /// # Note
    /// If the operation to determine the status fails, this function assumes that the process has exited.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        let mut exit_code = MaybeUninit::uninit();
        let result = unsafe { GetExitCodeProcess(self.handle(), exit_code.as_mut_ptr()) };
        result != FALSE && unsafe { exit_code.assume_init() } == 0
    }

    /// Returns the underlying raw process handle.
    #[must_use]
    pub fn handle(&self) -> ProcessHandle {
        self.as_raw_handle()
    }

    /// Promotes the given instance to an owning [`Process`] instance.
    pub fn promote_to_owned(borrowed: &Self) -> Result<Process, Win32Error> {
        let raw_handle = borrowed.as_raw_handle();
        let process = unsafe { GetCurrentProcess() };
        let mut new_handle = MaybeUninit::uninit();
        let result = unsafe {
            DuplicateHandle(
                process,
                raw_handle,
                process,
                new_handle.as_mut_ptr(),
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }
        Ok(unsafe { Process::from_raw_handle(new_handle.assume_init()) })
    }

    /// Returns the id of this process.
    pub fn pid(&self) -> Result<NonZeroU32, Win32Error> {
        let result = unsafe { GetProcessId(self.handle()) };
        NonZeroU32::new(result).ok_or_else(Win32Error::get_last_error)
    }

    /// Returns the handles of all the modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules the returned list may be incomplete.
    /// This can be worked around by repeatedly calling this method.
    pub fn module_handles(&self) -> Result<impl AsRef<[ModuleHandle]>, Win32Error> {
        let mut module_buf = UninitArrayBuf::<ModuleHandle, 1024>::new();
        let mut module_buf_byte_size = mem::size_of::<HMODULE>() * module_buf.len();
        let mut bytes_needed_target = MaybeUninit::uninit();
        let result = unsafe {
            EnumProcessModulesEx(
                self.handle(),
                module_buf.as_mut_ptr(),
                module_buf_byte_size.try_into().unwrap(),
                bytes_needed_target.as_mut_ptr(),
                LIST_MODULES_ALL,
            )
        };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }

        let mut bytes_needed = unsafe { bytes_needed_target.assume_init() } as usize;

        let modules = if bytes_needed <= module_buf_byte_size {
            // buffer size was sufficient
            let module_buf_len = bytes_needed / mem::size_of::<HMODULE>();
            let module_buf_init = unsafe { module_buf.assume_init_all() };
            ArrayOrVecSlice::from_array(module_buf_init, 0..module_buf_len)
        } else {
            // buffer size was not sufficient
            let mut module_buf_vec = Vec::new();

            // we loop here trying to find a buffer size that fits all handles
            // this needs to be a loop as the returned bytes_needed is only valid for the modules loaded when
            // the function run, if more modules have loaded in the meantime we need to resize the buffer again.
            // This can happen often if the process is currently starting up.
            loop {
                module_buf_byte_size = cmp::max(bytes_needed, module_buf_byte_size * 2);
                let mut module_buf_len = module_buf_byte_size / mem::size_of::<HMODULE>();
                module_buf_vec.resize_with(module_buf_len, MaybeUninit::uninit);

                bytes_needed_target = MaybeUninit::uninit();
                let result = unsafe {
                    EnumProcessModulesEx(
                        self.handle(),
                        module_buf_vec[0].as_mut_ptr(),
                        module_buf_byte_size.try_into().unwrap(),
                        bytes_needed_target.as_mut_ptr(),
                        LIST_MODULES_ALL,
                    )
                };
                if result == 0 {
                    return Err(Win32Error::get_last_error());
                }
                bytes_needed = unsafe { bytes_needed_target.assume_init() } as usize;

                if bytes_needed <= module_buf_byte_size {
                    module_buf_len = bytes_needed / mem::size_of::<HMODULE>();
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

    /// Searches the modules in this process for one with the given name.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules the returned list may be incomplete.
    /// This can be worked around by repeatedly calling this method.
    pub fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<'a>>, Win32Error> {
        let target_module_name = module_name.as_ref();

        // add default file extension if missing
        let target_module_name = if target_module_name.extension().is_some() {
            Cow::Owned(target_module_name.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_name.as_os_str())
        };

        let modules = self.module_handles()?;

        for &module_handle in modules.as_ref() {
            let module = unsafe { ProcessModule::new_unchecked(module_handle, *self) };
            let module_name = module.base_name()?;

            if module_name.eq_ignore_ascii_case(&target_module_name) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    /// Searches the modules in this process for one with the given path.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules the returned list may be incomplete.
    /// This can be worked around by repeatedly calling this method.
    pub fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<'a>>, Win32Error> {
        let target_module_path = module_path.as_ref();

        // add default file extension if missing
        let target_module_path = if target_module_path.extension().is_some() {
            Cow::Owned(target_module_path.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_path.as_os_str())
        };

        let modules = self.module_handles()?;

        for &module_handle in modules.as_ref() {
            let module = unsafe { ProcessModule::new_unchecked(module_handle, *self) };
            let module_path = module.path()?.into_os_string();

            if module_path.eq_ignore_ascii_case(&target_module_path) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    /// Searches the modules in this process for one with the given name repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<'a>>, Win32Error> {
        retry_with_filter(
            || self.find_module_by_name(module_name.as_ref()),
            Option::is_some,
            timeout,
        )
    }

    /// Searches the modules in this process for one with the given path repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    pub fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<'a>>, Win32Error> {
        retry_with_filter(
            || self.find_module_by_path(module_path.as_ref()),
            Option::is_some,
            timeout,
        )
    }

    /// Returns whether this process is running under [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications).
    /// This is the case for 32-bit programs running on an 64-bit platform.
    ///
    /// # Note
    /// This method returns `false` for a 32-bit process running under 32-bit Windows or 64-bit Windows 10 on ARM.
    pub fn is_wow64(&self) -> Result<bool, Win32Error> {
        let mut is_wow64 = MaybeUninit::uninit();
        let result = unsafe { IsWow64Process(self.handle(), is_wow64.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }
        Ok(unsafe { is_wow64.assume_init() } != FALSE)
    }

    /// Returns whether this process is a 64-bit process.
    pub fn is_x64(&self) -> Result<bool, Win32Error> {
        Ok(Self::is_x64_windows()? && !self.is_wow64()?)
    }

    /// Returns whether this process is a 32-bit process.
    pub fn is_x86(&self) -> Result<bool, Win32Error> {
        Ok(Self::is_x32_windows()? || Self::is_x64_windows()? && self.is_wow64()?)
    }

    fn is_x32_windows() -> Result<bool, Win32Error> {
        // TODO: cache?
        // TODO: use GetNativeSystemInfo() instead?
        let result = unsafe { GetSystemWow64DirectoryA(ptr::null_mut(), 0) };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }
        Ok(Win32Error::get_last_error().code() == ERROR_CALL_NOT_IMPLEMENTED)
    }
    fn is_x64_windows() -> Result<bool, Win32Error> {
        Self::is_x32_windows().map(|r| !r)
    }

    /// Gets the executable path of this process.
    pub fn path(&self) -> Result<PathBuf, Win32Error> {
        if self.is_current() {
            self._get_path_of_current()
        } else {
            self._get_path_of_remote()
        }
    }
    fn _get_path_of_current(&self) -> Result<PathBuf, Win32Error> {
        assert!(self.is_current());

        let mut module_path_buf = WinPathBuf::new();
        let module_path_buf_size: u32 = module_path_buf.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameW(
                ptr::null_mut(),
                module_path_buf.as_mut_ptr(),
                module_path_buf_size,
            )
        };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }

        let module_path_len = result as usize;
        let module_path = unsafe { module_path_buf.assume_init_path_buf(module_path_len) };
        Ok(module_path)
    }
    fn _get_path_of_remote(&self) -> Result<PathBuf, Win32Error> {
        assert!(!self.is_current());

        let mut module_path_buf = WinPathBuf::new();
        let module_path_buf_size: u32 = module_path_buf.len().try_into().unwrap();
        let result = unsafe {
            GetModuleFileNameExW(
                self.handle(),
                ptr::null_mut(),
                module_path_buf.as_mut_ptr(),
                module_path_buf_size,
            )
        };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }

        let module_path_len = result as usize;
        let module_path = unsafe { module_path_buf.assume_init_path_buf(module_path_len) };
        Ok(module_path)
    }

    /// Terminates this process with exit code 1.
    pub fn kill(self) -> Result<(), Win32Error> {
        self.kill_with_exit_code(1)
    }

    /// Terminates this process with the given exit code.
    pub fn kill_with_exit_code(self, exit_code: u32) -> Result<(), Win32Error> {
        let result = unsafe { TerminateProcess(self.handle(), exit_code) };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }
        Ok(())
    }

    /// Starts a new thread in this process with the given entry point and arguments and waits for it to finish, returning its exit code.
    pub fn run_remote_thread(
        &self,
        remote_fn: extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
    ) -> Result<u32, Win32Error> {
        let thread_handle = self.start_remote_thread(remote_fn, parameter)?;

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(Win32Error::get_last_error());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }
        assert_ne!(
            result as u32, STILL_ACTIVE,
            "GetExitCodeThread returned STILL_ACTIVE after WaitForSingleObject"
        );

        Ok(unsafe { exit_code.assume_init() })
    }

    /// Starts a new thread in this process with the given entry point and arguments and returns its thread handle.
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // not relevant as ptr is dereffed in the target process and any invalid deref will only result in an error.
    pub fn start_remote_thread(
        &self,
        remote_fn: extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
    ) -> Result<OwnedHandle, Win32Error> {
        // create a remote thread that will call LoadLibraryW with payload_path as its argument.
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.handle(),
                ptr::null_mut(),
                0,
                Some(remote_fn),
                parameter,
                0, // RUN_IMMEDIATELY
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(Win32Error::get_last_error());
        }

        Ok(unsafe { OwnedHandle::from_raw_handle(thread_handle) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_current() {
        let process = ProcessRef::current();
        assert!(process.is_current());

        let process = Process::from_pid(process.pid().unwrap().get()).unwrap();
        assert!(process.is_current());
    }

    #[test]
    fn remote_process_is_not_current() {
        let mut all = Process::all().into_iter();
        let process_a = all.next().unwrap();
        let process_b = all.next().unwrap();
        assert!(!process_a.is_current() || !process_b.is_current());
    }

    #[test]
    fn current_pseudo_process_eq_current_process() {
        let pseudo = ProcessRef::current();
        let normal = Process::from_pid(pseudo.pid().unwrap().get()).unwrap();

        assert_eq!(pseudo, normal.get_ref());
        assert_eq!(pseudo, normal);
        assert_eq!(ProcessRef::promote_to_owned(&pseudo).unwrap(), normal);
        assert_eq!(pseudo, ProcessRef::promote_to_owned(&normal).unwrap());
    }
}
