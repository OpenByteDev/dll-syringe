use std::{
    ffi::OsString,
    io,
    mem::{self, MaybeUninit},
    num::NonZeroU32,
    os::windows::prelude::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INSUFFICIENT_BUFFER},
    },
    um::{
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{
            CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread,
            GetProcessId, TerminateProcess,
        },
        synchapi::WaitForSingleObject,
        winbase::{QueryFullProcessImageNameW, INFINITE, WAIT_FAILED},
        winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
        wow64apiset::{GetSystemWow64DirectoryA, IsWow64Process},
    },
};

use crate::{
    process::{BorrowedProcess, ProcessModule},
    utils::{win_fill_path_buf_helper, FillPathBufResult},
};

/// A handle to a running process.
pub type ProcessHandle = std::os::windows::raw::HANDLE;

/// The [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) required for a process handle to be usable for dll injection.
pub const PROCESS_INJECTION_ACCESS: DWORD = PROCESS_CREATE_THREAD
    | PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE;

/// A trait representing a running process.
///
/// # Note
/// The underlying handle has the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
pub trait Process: AsHandle + AsRawHandle {
    /// The underlying handle type.
    type Handle;

    /// Returns a borrowed instance of this process.
    fn borrowed(&self) -> BorrowedProcess<'_>;

    /// Tries to clone this process into a new instance.
    fn try_clone(&self) -> Result<Self, io::Error>
    where
        Self: Sized;

    /// Returns the underlying process handle.
    #[must_use]
    fn into_handle(self) -> Self::Handle;

    /// Creates a new instance from the given handle.
    ///
    /// # Safety
    /// The caller must ensure that the handle is a valid process handle and has the required priviledges.
    #[must_use]
    unsafe fn from_handle_unchecked(handle: Self::Handle) -> Self;

    /// Returns the raw pseudo handle representing the current process.
    #[must_use]
    fn raw_current_handle() -> ProcessHandle {
        unsafe { GetCurrentProcess() }
    }

    /// Returns the pseudo handle representing the current process.
    #[must_use]
    fn current_handle() -> Self::Handle;

    /// Returns an instance representing the current process.
    #[must_use]
    fn current() -> Self
    where
        Self: Sized,
    {
        unsafe { Self::from_handle(Self::current_handle()) }
    }

    /// Returns whether this instance represents the current process.
    #[must_use]
    fn is_current(&self) -> bool {
        self.borrowed() == BorrowedProcess::current()
    }

    /// Returns whether this process is still alive and running.
    ///
    /// # Note
    /// If the operation to determine the status fails, this function assumes that the process has exited.
    #[must_use]
    fn is_alive(&self) -> bool {
        let mut exit_code = MaybeUninit::uninit();
        let result = unsafe { GetExitCodeProcess(self.as_raw_handle(), exit_code.as_mut_ptr()) };
        result != FALSE && unsafe { exit_code.assume_init() } == STILL_ACTIVE
    }

    /// Returns the id of this process.
    fn pid(&self) -> Result<NonZeroU32, io::Error> {
        let result = unsafe { GetProcessId(self.as_raw_handle()) };
        NonZeroU32::new(result).ok_or_else(io::Error::last_os_error)
    }

    /// Returns whether this process is running under [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications).
    /// This is the case for 32-bit programs running on a 64-bit platform.
    ///
    /// # Note
    /// This method also returns `false` for a 32-bit process running under 32-bit Windows or 64-bit Windows 10 on ARM.
    fn runs_under_wow64(&self) -> Result<bool, io::Error> {
        let mut is_wow64 = MaybeUninit::uninit();
        let result = unsafe { IsWow64Process(self.as_raw_handle(), is_wow64.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { is_wow64.assume_init() } != FALSE)
    }

    /// Returns whether this process is a 64-bit process.
    fn is_x64(&self) -> Result<bool, io::Error> {
        Ok(is_x64_windows()? && !self.runs_under_wow64()?)
    }

    /// Returns whether this process is a 32-bit process.
    fn is_x86(&self) -> Result<bool, io::Error> {
        Ok(is_x32_windows()? || is_x64_windows()? && self.runs_under_wow64()?)
    }

    /// Returns the executable path of this process.
    fn path(&self) -> Result<PathBuf, io::Error> {
        win_fill_path_buf_helper(|buf_ptr, buf_size| {
            let mut buf_size = buf_size as u32;
            let result = unsafe {
                QueryFullProcessImageNameW(self.as_raw_handle(), 0, buf_ptr, &mut buf_size)
            };
            if result == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error().unwrap() == ERROR_INSUFFICIENT_BUFFER as i32 {
                    FillPathBufResult::BufTooSmall {
                        size_hint: Some(buf_size as usize),
                    }
                } else {
                    FillPathBufResult::Error(err)
                }
            } else {
                FillPathBufResult::Success {
                    actual_len: buf_size as usize,
                }
            }
        })
    }

    /// Returns the file name of the executable of this process.
    fn base_name(&self) -> Result<OsString, io::Error> {
        self.path()
            .map(|path| path.file_name().unwrap().to_os_string())
    }

    /// Terminates this process with exit code 1.
    fn kill(&self) -> Result<(), io::Error> {
        self.kill_with_exit_code(1)
    }

    /// Terminates this process with the given exit code.
    fn kill_with_exit_code(&self, exit_code: u32) -> Result<(), io::Error> {
        let result = unsafe { TerminateProcess(self.as_raw_handle(), exit_code) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Starts a new thread in this process with the given entry point and argument, and waits for it to finish, returning the exit code.
    fn run_remote_thread<T>(
        &self,
        remote_fn: extern "system" fn(*mut T) -> u32,
        parameter: *mut T,
    ) -> Result<u32, io::Error> {
        let thread_handle = self.start_remote_thread(remote_fn, parameter)?;

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        debug_assert_ne!(
            result as u32, STILL_ACTIVE,
            "GetExitCodeThread returned STILL_ACTIVE after WaitForSingleObject"
        );

        Ok(unsafe { exit_code.assume_init() })
    }

    /// Starts a new thread in this process with the given entry point and argument and returns the thread handle.
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // not relevant as ptr is dereffed in the target process and any invalid deref will only result in an io::Error.
    fn start_remote_thread<T>(
        &self,
        remote_fn: unsafe extern "system" fn(*mut T) -> u32,
        parameter: *mut T,
    ) -> Result<OwnedHandle, io::Error> {
        // create a remote thread that will call LoadLibraryW with payload_path as its argument.
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.as_raw_handle(),
                ptr::null_mut(),
                0,
                Some(mem::transmute(remote_fn)),
                parameter.cast(),
                0, // RUN_IMMEDIATELY
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { OwnedHandle::from_raw_handle(thread_handle) })
    }

    /// Searches the modules in this process for one with the given name.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_name`].
    fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given path.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules, the returned list may be incomplete.
    /// See also [`Process::wait_for_module_by_path`].
    fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given name, repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of names is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Searches the modules in this process for one with the given path, repeatedly until a matching module is found or the given timeout elapses.
    /// The comparison of paths is case-insensitive.
    /// If the extension is omitted, the default library extension `.dll` is appended.
    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<Self>>, io::Error>
    where
        Self: Sized;

    /// Returns a snapshot of all modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not loaded all its modules yet, the returned list may be incomplete.
    fn modules(&self) -> Result<Vec<ProcessModule<Self>>, io::Error>
    where
        Self: Sized,
    {
        let module_handles = self.borrowed().module_handles()?;
        let mut modules = Vec::with_capacity(module_handles.len());
        for module_handle in module_handles {
            modules.push(unsafe { ProcessModule::new_unchecked(module_handle, self.try_clone()?) });
        }
        Ok(modules)
    }
}

fn is_x32_windows() -> Result<bool, io::Error> {
    // TODO: use GetNativeSystemInfo() instead?
    let result = unsafe { GetSystemWow64DirectoryA(ptr::null_mut(), 0) };
    if result == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error().unwrap() == ERROR_CALL_NOT_IMPLEMENTED as _ {
            Ok(true)
        } else {
            Err(err)
        }
    } else {
        Ok(false)
    }
}

fn is_x64_windows() -> Result<bool, io::Error> {
    if cfg!(target_arch = "x86_64") {
        Ok(true)
    } else {
        Ok(!is_x32_windows()?)
    }
}
