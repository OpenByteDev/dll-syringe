use std::{
    hash::{Hash, Hasher},
    io,
    ops::{Deref, DerefMut},
    os::windows::{
        prelude::{
            AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
            RawHandle,
        },
        raw::HANDLE,
    },
    process::Child,
};

use sysinfo::{PidExt, ProcessExt, SystemExt};
use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        processthreadsapi::OpenProcess,
        winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::ProcessRef;

/// A handle to a process.
/// Equivalent to [`HANDLE`](std::os::windows::raw::HANDLE).
pub type ProcessHandle = std::os::windows::raw::HANDLE;

/// The [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) required for a process handle to be usable for dll injection.
pub const PROCESS_INJECTION_ACCESS: DWORD = PROCESS_CREATE_THREAD
    | PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE;

/// A struct representing a running process (including the current one).
/// This struct owns the underlying process handle.
///
/// # Note
/// The underlying handle has the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
#[repr(transparent)]
#[derive(Debug)]
pub struct Process(OwnedHandle);

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl AsRawHandle for Process {
    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

impl IntoRawHandle for Process {
    fn into_raw_handle(self) -> RawHandle {
        self.0.into_raw_handle()
    }
}

impl FromRawHandle for Process {
    unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

impl AsHandle for Process {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl From<Child> for Process {
    fn from(child: Child) -> Self {
        Self::from_child(child)
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        self.get_ref() == other.get_ref()
    }
}

impl Eq for Process {}

impl Hash for Process {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_ref().hash(state);
    }
}

impl Deref for Process {
    type Target = ProcessRef<'static>;

    fn deref(&self) -> &Self::Target {
        // Safety: ProcessRef is layout-compatible with Process.
        unsafe {
            &*(&self.0 as *const OwnedHandle as *const BorrowedHandle<'_> as *const ProcessRef<'_>)
        }
    }
}

impl DerefMut for Process {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: ProcessRef is layout-compatible with Process.
        unsafe {
            &mut *(&mut self.0 as *mut OwnedHandle as *mut BorrowedHandle<'_>
                as *mut ProcessRef<'_>)
        }
    }
}

impl AsRef<ProcessRef<'static>> for Process {
    fn as_ref(&self) -> &ProcessRef<'static> {
        self.deref()
    }
}

impl AsMut<ProcessRef<'static>> for Process {
    fn as_mut(&mut self) -> &mut ProcessRef<'static> {
        self.deref_mut()
    }
}

// Creation and Destruction
impl Process {
    /// Creates a new instance from the given pid.
    pub fn from_pid(pid: u32) -> Result<Self, io::Error> {
        let handle = unsafe {
            OpenProcess(
                // access required for performing dll injection
                PROCESS_INJECTION_ACCESS,
                FALSE,
                pid,
            )
        };

        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { Self::from_raw_handle(handle) })
    }

    /// Returns a list of all currently running processes.
    #[must_use]
    pub fn all() -> Vec<Self> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system
            .processes()
            .values()
            .map(|process| process.pid())
            .filter_map(|pid| Process::from_pid(pid.as_u32()).ok())
            .collect()
    }

    /// Finds all processes whose name contains the given string.
    #[must_use]
    pub fn find_all_by_name(name: impl AsRef<str>) -> Vec<Self> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system
            .processes()
            .values()
            .filter(move |process| process.name().contains(name.as_ref()))
            .map(|process| process.pid())
            .filter_map(|pid| Process::from_pid(pid.as_u32()).ok())
            .collect()
    }

    /// Finds the first process whose name contains the given string.
    #[must_use]
    pub fn find_first_by_name(name: impl AsRef<str>) -> Option<Self> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system
            .processes()
            .values()
            .filter(move |process| process.name().contains(name.as_ref()))
            .map(|process| process.pid())
            .find_map(|pid| Process::from_pid(pid.as_u32()).ok())
    }

    /// Creates a new instance from the given child process.
    #[must_use]
    pub fn from_child(child: Child) -> Self {
        unsafe { Self::from_raw_handle(child.into_raw_handle()) }
    }

    /// Creates a new non-owning [`ProcessRef`] instance for this process.
    #[must_use]
    pub fn get_ref(&'_ self) -> ProcessRef<'_> {
        unsafe { ProcessRef::borrow_from_handle(self.as_handle()) }
    }

    /// Creates a new owning [`Process`] instance for this process by duplicating the underlying handle.
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        ProcessRef::promote_to_owned(&self.get_ref())
    }

    /// Leaks the underlying handle and return it as a non-owning [`ProcessRef`] instance.
    #[allow(clippy::must_use_candidate)]
    pub fn leak(self) -> ProcessRef<'static> {
        unsafe {
            ProcessRef::borrow_from_handle(BorrowedHandle::borrow_raw_handle(
                self.into_raw_handle(),
            ))
        }
    }

    /// Returns a [`ProcessKillGuard`] wrapping this process that will automatically kill this process when dropped.
    #[must_use]
    pub const fn kill_on_drop(self) -> ProcessKillGuard {
        ProcessKillGuard(self)
    }
}

#[derive(Debug, shrinkwraprs::Shrinkwrap)]
#[shrinkwrap(mutable)]
/// A guard wrapping a [`Process`] that will be automatically killed on drop.
pub struct ProcessKillGuard(pub Process);

impl Drop for ProcessKillGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}
