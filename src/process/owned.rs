use std::{
    hash::{Hash, Hasher},
    io,
    os::windows::{
        prelude::{
            AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
            RawHandle,
        },
        raw::HANDLE,
    },
    path::Path,
    process::Child,
    time::Duration,
};

use winapi::{shared::minwindef::FALSE, um::processthreadsapi::OpenProcess};

use crate::process::{BorrowedProcess, OwnedProcessModule, Process, PROCESS_INJECTION_ACCESS};

/// A struct representing a running process.
/// This struct owns the underlying process handle (see also [`BorrowedProcess`] for a borrowed version).
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
pub struct OwnedProcess(OwnedHandle);

unsafe impl Send for OwnedProcess {}
unsafe impl Sync for OwnedProcess {}

impl AsRawHandle for OwnedProcess {
    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

impl AsHandle for OwnedProcess {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl IntoRawHandle for OwnedProcess {
    fn into_raw_handle(self) -> RawHandle {
        self.0.into_raw_handle()
    }
}

impl FromRawHandle for OwnedProcess {
    unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

impl From<Child> for OwnedProcess {
    fn from(child: Child) -> Self {
        Self::from_child(child)
    }
}

impl TryFrom<BorrowedProcess<'_>> for OwnedProcess {
    type Error = io::Error;

    fn try_from(process: BorrowedProcess<'_>) -> Result<Self, Self::Error> {
        process.try_to_owned()
    }
}

impl PartialEq for OwnedProcess {
    fn eq(&self, other: &Self) -> bool {
        self.borrowed() == other.borrowed()
    }
}

impl Eq for OwnedProcess {}

impl Hash for OwnedProcess {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.borrowed().hash(state);
    }
}

impl Process for OwnedProcess {
    type Handle = OwnedHandle;

    fn borrowed(&self) -> BorrowedProcess<'_> {
        unsafe { BorrowedProcess::from_handle_unchecked(self.as_handle()) }
    }

    fn try_clone(&self) -> Result<Self, io::Error> {
        self.borrowed().try_to_owned()
    }

    fn into_handle(self) -> Self::Handle {
        self.0
    }

    unsafe fn from_handle_unchecked(handle: Self::Handle) -> Self {
        Self(handle)
    }

    fn current_handle() -> Self::Handle {
        unsafe { OwnedHandle::from_raw_handle(Self::raw_current_handle()) }
    }

    fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<OwnedProcessModule>, io::Error> {
        if let Some(module) = self.borrowed().find_module_by_name(module_name)? {
            Ok(Some(module.try_to_owned()?))
        } else {
            Ok(None)
        }
    }

    fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<OwnedProcessModule>, io::Error> {
        if let Some(module) = self.borrowed().find_module_by_path(module_path)? {
            Ok(Some(module.try_to_owned()?))
        } else {
            Ok(None)
        }
    }

    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<OwnedProcessModule>, io::Error> {
        if let Some(module) = self
            .borrowed()
            .wait_for_module_by_name(module_name, timeout)?
        {
            Ok(Some(module.try_to_owned()?))
        } else {
            Ok(None)
        }
    }

    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<OwnedProcessModule>, io::Error> {
        if let Some(module) = self
            .borrowed()
            .wait_for_module_by_path(module_path, timeout)?
        {
            Ok(Some(module.try_to_owned()?))
        } else {
            Ok(None)
        }
    }
}

impl OwnedProcess {
    /// Creates a new instance from the given pid.
    pub fn from_pid(pid: u32) -> Result<OwnedProcess, io::Error> {
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

        Ok(unsafe { OwnedProcess::from_raw_handle(handle.cast()) })
    }

    /// Returns a list of all currently running processes.
    #[must_use]
    pub fn all() -> Vec<OwnedProcess> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        system
            .processes()
            .values()
            .map(|process| process.pid())
            .filter_map(|pid| OwnedProcess::from_pid(pid.as_u32()).ok())
            .collect()
    }

    /// Finds all processes whose name contains the given string.
    #[must_use]
    pub fn find_all_by_name(name: impl AsRef<str>) -> Vec<OwnedProcess> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        system
            .processes()
            .values()
            .filter(move |process| process.name().to_string_lossy().contains(name.as_ref()))
            .map(|process| process.pid())
            .filter_map(|pid| OwnedProcess::from_pid(pid.as_u32()).ok())
            .collect()
    }

    /// Finds the first process whose name contains the given string.
    #[must_use]
    pub fn find_first_by_name(name: impl AsRef<str>) -> Option<OwnedProcess> {
        // TODO: avoid using sysinfo for this
        // TODO: deduplicate code
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        system
            .processes()
            .values()
            .filter(move |process| process.name().to_string_lossy().contains(name.as_ref()))
            .map(|process| process.pid())
            .find_map(|pid| OwnedProcess::from_pid(pid.as_u32()).ok())
    }

    /// Creates a new instance from the given child process.
    #[must_use]
    pub fn from_child(child: Child) -> OwnedProcess {
        unsafe { OwnedProcess::from_raw_handle(child.into_raw_handle()) }
    }

    /// Returns a borrowed instance of this process that lives for `'static`.
    ///
    /// # Safety
    /// - This method is unsafe as the returned instance can outlive the owned instance,
    ///   thus the caller must guarantee that the owned instance outlives the returned instance.
    #[must_use]
    pub unsafe fn borrowed_static(&self) -> BorrowedProcess<'static> {
        unsafe {
            BorrowedProcess::from_handle_unchecked(BorrowedHandle::borrow_raw(self.as_raw_handle()))
        }
    }

    /// Creates a new owning [`Process`] instance for this process by duplicating the underlying handle.
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        self.borrowed().try_to_owned()
    }

    /// Leaks the underlying handle and return it as a non-owning [`BorrowedProcess`] instance.
    #[allow(clippy::must_use_candidate)]
    pub fn leak(self) -> BorrowedProcess<'static> {
        unsafe { self.borrowed_static() }
    }

    /// Returns a [`ProcessKillGuard`] wrapping this process that will automatically kill this process when dropped.
    #[must_use]
    pub const fn kill_on_drop(self) -> ProcessKillGuard {
        ProcessKillGuard(self)
    }
}

#[derive(Debug, shrinkwraprs::Shrinkwrap)]
#[shrinkwrap(mutable)]
/// A guard wrapping a [`OwnedProcess`] that will be automatically killed on drop.
pub struct ProcessKillGuard(pub OwnedProcess);

impl Drop for ProcessKillGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}
