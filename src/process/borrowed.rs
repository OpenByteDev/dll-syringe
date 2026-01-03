use std::{
    borrow::Cow,
    cmp,
    hash::{Hash, Hasher},
    io,
    mem::{self, MaybeUninit},
    os::windows::{
        prelude::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle},
        raw::HANDLE,
    },
    path::Path,
    time::Duration,
};

use winapi::{
    shared::{
        minwindef::{FALSE, HMODULE},
        winerror::ERROR_PARTIAL_COPY,
    },
    um::{
        handleapi::DuplicateHandle,
        processthreadsapi::GetCurrentProcess,
        psapi::{EnumProcessModulesEx, LIST_MODULES_ALL},
        winnt::DUPLICATE_SAME_ACCESS,
    },
};

use crate::{
    process::{ModuleHandle, OwnedProcess, Process, ProcessModule},
    utils::{retry_faillable_until_some_with_timeout, ArrayOrVecBuf},
};

/// A struct representing a running process.
/// This struct does **NOT** own the underlying process handle (see also [`OwnedProcess`] for an owned version).
///
/// # Note
/// The underlying handle has the following [privileges](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):
///  - `PROCESS_CREATE_THREAD`
///  - `PROCESS_QUERY_INFORMATION`
///  - `PROCESS_VM_OPERATION`
///  - `PROCESS_VM_WRITE`
///  - `PROCESS_VM_READ`
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct BorrowedProcess<'a>(BorrowedHandle<'a>);

unsafe impl Send for BorrowedProcess<'_> {}
unsafe impl Sync for BorrowedProcess<'_> {}

impl AsRawHandle for BorrowedProcess<'_> {
    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

impl AsHandle for BorrowedProcess<'_> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }
}

impl<'a> PartialEq<BorrowedProcess<'a>> for BorrowedProcess<'_> {
    fn eq(&self, other: &BorrowedProcess<'a>) -> bool {
        // TODO: (unsafe { CompareObjectHandles(self.handle(), other.handle()) }) != FALSE

        self.as_raw_handle() == other.as_raw_handle()
            || self.pid().map_or(0, |v| v.get()) == other.pid().map_or(0, |v| v.get())
    }
}

impl PartialEq<OwnedProcess> for BorrowedProcess<'_> {
    fn eq(&self, other: &OwnedProcess) -> bool {
        self == &other.borrowed()
    }
}

impl PartialEq<BorrowedProcess<'_>> for OwnedProcess {
    fn eq(&self, other: &BorrowedProcess<'_>) -> bool {
        &self.borrowed() == other
    }
}

impl Eq for BorrowedProcess<'_> {}

impl Hash for BorrowedProcess<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw_handle().hash(state);
    }
}

impl<'a> From<&'a OwnedProcess> for BorrowedProcess<'a> {
    fn from(process: &'a OwnedProcess) -> Self {
        process.borrowed()
    }
}

#[cfg(feature = "try-clone")]
impl try_clone::TryClone for BorrowedProcess<'_> {
    type Error = core::convert::Infallible;

    fn try_clone(&self) -> Result<Self, Self::Error> {
       BorrowedProcess::try_clone(self)
    }
}

#[cfg(feature = "try-clone")]
impl try_clone::TryCloneToOwned for BorrowedProcess<'_> {
    type Owned = OwnedProcess;
    type Error = io::Error;

    fn try_clone_to_owned(&self) -> Result<Self::Owned, Self::Error> {
        self.try_to_owned()
    }
}

impl<'a> Process for BorrowedProcess<'a> {
    type Handle = BorrowedHandle<'a>;

    fn borrowed(&self) -> BorrowedProcess<'a> {
        *self
    }

    fn into_handle(self) -> Self::Handle {
        self.0
    }

    fn try_clone(&self) -> Result<Self, io::Error> {
        Ok(*self)
    }

    unsafe fn from_handle_unchecked(handle: Self::Handle) -> Self {
        Self(handle)
    }

    fn current_handle() -> Self::Handle {
        unsafe { BorrowedHandle::borrow_raw(Self::raw_current_handle()) }
    }

    fn find_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, io::Error> {
        let target_module_name = module_name.as_ref();

        // add default file extension if missing
        let target_module_name = if target_module_name.extension().is_none() {
            Cow::Owned(target_module_name.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_name.as_os_str())
        };

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle, *self) };
            let module_name = module.base_name()?;

            if module_name.eq_ignore_ascii_case(&target_module_name) {
                return Ok(Some(module));
            }
        }

        Ok(None)
    }

    fn find_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, io::Error> {
        let target_module_path = module_path.as_ref();

        // add default file extension if missing
        let target_module_path = if target_module_path.extension().is_none() {
            Cow::Owned(target_module_path.with_extension("dll").into_os_string())
        } else {
            Cow::Borrowed(target_module_path.as_os_str())
        };

        let target_module_handle = same_file::Handle::from_path(&target_module_path)?;

        let modules = self.module_handles()?;

        for module_handle in modules {
            let module = unsafe { ProcessModule::new_unchecked(module_handle, *self) };
            let module_path = module.path()?.into_os_string();

            match same_file::Handle::from_path(&module_path) {
                Ok(module_handle) => {
                    if module_handle == target_module_handle {
                        return Ok(Some(module));
                    }
                }
                Err(_) => {
                    if target_module_path.eq_ignore_ascii_case(&module_path) {
                        return Ok(Some(module));
                    }
                }
            }
        }

        Ok(None)
    }

    fn wait_for_module_by_name(
        &self,
        module_name: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, io::Error> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_name(module_name.as_ref()),
            timeout,
        )
    }

    fn wait_for_module_by_path(
        &self,
        module_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Option<ProcessModule<BorrowedProcess<'a>>>, io::Error> {
        retry_faillable_until_some_with_timeout(
            || self.find_module_by_path(module_path.as_ref()),
            timeout,
        )
    }
}

impl BorrowedProcess<'_> {
    /// Tries to create a new [`OwnedProcess`] instance for this process.
    pub fn try_to_owned(&self) -> Result<OwnedProcess, io::Error> {
        let raw_handle = self.as_raw_handle();
        let process = unsafe { GetCurrentProcess() };
        let mut new_handle = MaybeUninit::uninit();
        let result = unsafe {
            DuplicateHandle(
                process,
                raw_handle.cast(),
                process,
                new_handle.as_mut_ptr(),
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedProcess::from_raw_handle(new_handle.assume_init().cast()) })
    }

    /// Returns a snapshot of the handles of the modules currently loaded in this process.
    ///
    /// # Note
    /// If the process is currently starting up and has not yet loaded all its modules, the returned list may be incomplete.
    /// This can be worked around by repeatedly calling this method.
    pub fn module_handles(&self) -> Result<impl ExactSizeIterator<Item = ModuleHandle>, io::Error> {
        const HANDLE_SIZE: u32 = mem::size_of::<HMODULE>() as _;

        let mut module_buf = ArrayOrVecBuf::<ModuleHandle, 1024>::new_uninit_array();
        let mut module_buf_byte_size = HANDLE_SIZE * module_buf.capacity() as u32;
        let mut bytes_needed_new = MaybeUninit::uninit();
        loop {
            let result = unsafe {
                EnumProcessModulesEx(
                    self.as_raw_handle().cast(),
                    module_buf.as_mut_ptr(),
                    module_buf_byte_size,
                    bytes_needed_new.as_mut_ptr(),
                    LIST_MODULES_ALL,
                )
            };
            if result == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_PARTIAL_COPY.cast_signed()) && self.is_alive() {
                    continue;
                }
                return Err(err);
            }

            break;
        }

        let mut bytes_needed = unsafe { bytes_needed_new.assume_init() };

        let modules = if bytes_needed <= module_buf_byte_size {
            // buffer size was sufficient
            let module_buf_len = (bytes_needed / HANDLE_SIZE) as usize;
            unsafe { module_buf.set_len(module_buf_len) };
            module_buf
        } else {
            // buffer size was not sufficient
            let mut module_buf_vec = Vec::new();

            // we loop here trying to find a buffer size that fits all handles
            // this needs to be a loop as the returned bytes_needed is only valid for the modules loaded when
            // the function run, if more modules have loaded in the meantime we need to resize the buffer again.
            // This can happen often if the process is currently starting up.
            loop {
                module_buf_byte_size =
                    cmp::max(bytes_needed, module_buf_byte_size.saturating_mul(2));
                let mut module_buf_len = (module_buf_byte_size / HANDLE_SIZE) as usize;
                if module_buf_len > module_buf_vec.capacity() {
                    module_buf_vec.reserve(module_buf_len - module_buf_vec.capacity());
                }

                let mut bytes_needed_new = MaybeUninit::uninit();
                let result = unsafe {
                    EnumProcessModulesEx(
                        self.as_raw_handle().cast(),
                        module_buf_vec.as_mut_ptr(),
                        module_buf_byte_size,
                        bytes_needed_new.as_mut_ptr(),
                        LIST_MODULES_ALL,
                    )
                };
                if result == 0 {
                    return Err(io::Error::last_os_error());
                }
                bytes_needed = unsafe { bytes_needed_new.assume_init() };

                if bytes_needed <= module_buf_byte_size {
                    module_buf_len = (bytes_needed / HANDLE_SIZE) as usize;
                    unsafe { module_buf_vec.set_len(module_buf_len) };
                    break ArrayOrVecBuf::from_vec(module_buf_vec);
                }
            }
        };

        debug_assert!(modules.iter().all(|module| !module.is_null()));

        Ok(modules.into_iter())
    }
}
