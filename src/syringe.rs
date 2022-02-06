use cstr::cstr;
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "into_x86_from_x64")]
use goblin::pe::PE;
use path_absolutize::Absolutize;
use rust_win32error::Win32Error;
use std::{
    convert::TryInto,
    fs,
    lazy::OnceCell,
    mem::{self, MaybeUninit},
    path::{Path, PathBuf},
    time::Duration,
};
use u16cstr::u16cstr;
use widestring::{U16CString, U16Str};
use winapi::{
    shared::{
        minwindef::{BOOL, FARPROC, HMODULE, MAX_PATH},
        ntdef::{LPCSTR, LPCWSTR},
    },
    um::{
        wow64apiset::GetSystemWow64DirectoryW,
    },
};

use crate::{
    error::InjectError, utils::retry_with_filter, ModuleHandle, ProcessModule, ProcessRef, RemoteBoxAllocator,
};

type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FreeLibraryFn = unsafe extern "system" fn(HMODULE) -> BOOL;
type GetProcAddressFn = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

#[derive(Debug, Clone)]
pub(crate) struct InjectHelpData {
    kernel32_module: ModuleHandle,
    load_library_offset: usize,
    free_library_offset: usize,
    get_proc_address_offset: usize,
}

unsafe impl Send for InjectHelpData {}

impl InjectHelpData {
    pub fn get_load_library_fn_ptr(&self) -> LoadLibraryWFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.load_library_offset) }
    }
    pub fn get_free_library_fn_ptr(&self) -> FreeLibraryFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.free_library_offset) }
    }
    pub fn get_proc_address_fn_ptr(&self) -> GetProcAddressFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.get_proc_address_offset) }
    }
}

/// An injector that can inject modules (.dll's) into processes.
/// This struct keeps internal state to allow for faster injcetions if reused.
///
/// # Example
/// ```no_run
/// use dll_syringe::{Syringe, Process};
///
/// // find target process by name
/// let target_process = Process::find_first_by_name("target_process").unwrap();
///
/// // create a new syringe for the target process
/// let mut syringe = Syringe::for_process(&target_process);
///
/// // inject the payload into the target process
/// let injected_payload = syringe.inject("injection_payload.dll").unwrap();
///
/// // do something else
///
/// // eject the payload from the target (optional)
/// syringe.eject(injected_payload).unwrap();
/// ```
#[derive(Debug)]
pub struct Syringe<'a> {
    pub(crate) process: ProcessRef<'a>,
    pub(crate) inject_help_data: OnceCell<InjectHelpData>,
    pub(crate) remote_allocator: RemoteBoxAllocator<'a>,
    #[cfg(feature = "remote_procedure")]
    pub(crate) get_proc_address_stub:
        OnceCell<crate::RemoteProcedureStub<'a, crate::GetProcAddressParams, FARPROC>>,
}

impl<'a> Syringe<'a> {
    /// Creates a new syringe for the given process.
    pub fn for_process(process: impl Into<ProcessRef<'a>>) -> Self {
        let process = process.into();
        Self {
            process,
            inject_help_data: OnceCell::new(),
            remote_allocator: RemoteBoxAllocator::new(process),
            #[cfg(feature = "remote_procedure")]
            get_proc_address_stub: OnceCell::new(),
        }
    }

    /// Inject the module at the given path into the target process.
    ///
    /// # Limitations
    /// - The target process and the given module need to be of the same bitness.
    /// - If the current process is `x64` the target process can be either `x64` (always available) or `x86` (with the `into_x86_from_x64` feature enabled).
    /// - If the current process is `x86` the target process can only be `x86`.
    pub fn inject(
        &mut self,
        payload_path: impl AsRef<Path>,
    ) -> Result<ProcessModule<'a>, InjectError> {
        let inject_data = self
            .inject_help_data
            .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process))?;
        let module_path = payload_path.as_ref().absolutize()?;

        let wide_module_path =
            U16CString::from_os_str(module_path.as_os_str())?.into_vec_with_nul();
        let mut remote_wide_module_path = self
            .remote_allocator
            .alloc_and_copy(wide_module_path.as_slice())?;

        // creating a thread that will call LoadLibraryW with a pointer to payload_path as argument
        let exit_code = self.process.run_remote_thread(
            unsafe { mem::transmute(inject_data.get_load_library_fn_ptr()) },
            remote_wide_module_path.as_mut_ptr().cast(),
        )?;

        // reinterpret the possibly truncated exit code as a truncated handle to the loaded module
        let truncated_injected_module_handle = exit_code as ModuleHandle;
        if truncated_injected_module_handle.is_null() {
            return Err(InjectError::RemoteOperationFailed);
        }

        let injected_module = self.process.find_module_by_path(module_path)?.unwrap();
        assert_eq!(
            injected_module.handle() as u32,
            truncated_injected_module_handle as u32
        );

        Ok(injected_module)
    }

    /// Ejects a previously injected module from its target process.
    pub fn eject(&self, module: ProcessModule<'_>) -> Result<(), InjectError> {
        if module.process() != self.process {
            panic!("ejecting a module from a different process");
        }

        let inject_data = self
            .inject_help_data
            .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process))?;

        let exit_code = self.process.run_remote_thread(
            unsafe { mem::transmute(inject_data.get_free_library_fn_ptr()) },
            module.handle().cast(),
        )?;

        let free_library_result = exit_code as BOOL;
        if free_library_result == 0 {
            return Err(InjectError::RemoteOperationFailed);
        }

        assert!(!self
            .process
            .module_handles()?
            .as_ref()
            .contains(&module.handle()));

        Ok(())
    }

    pub(crate) fn load_inject_help_data_for_process(
        process: ProcessRef<'_>,
    ) -> Result<InjectHelpData, InjectError> {
        let is_target_x64 = process.is_x64()?;
        let is_self_x64 = cfg!(target_arch = "x86_64");

        match (is_target_x64, is_self_x64) {
            (true, true) | (false, false) => Self::load_inject_help_data_for_current_target(),
            #[cfg(all(target_arch = "x86_64", feature = "into_x86_from_x64"))]
            (false, true) => Self::_load_inject_help_data_for_process(process),
            _ => Err(InjectError::UnsupportedTarget),
        }
    }

    fn load_inject_help_data_for_current_target() -> Result<InjectHelpData, InjectError> {
        let kernel32_module =
            ProcessModule::__find_local_by_name_or_abs_path(u16cstr!("kernel32.dll"))?.unwrap();
        let load_library_fn_ptr = kernel32_module
            .__get_procedure(cstr!("LoadLibraryW"))
            .unwrap();
        let free_library_fn_ptr = kernel32_module
            .__get_procedure(cstr!("FreeLibrary"))
            .unwrap();
        let get_proc_address_fn_ptr = kernel32_module
            .__get_procedure(cstr!("GetProcAddress"))
            .unwrap();

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_fn_ptr as usize - kernel32_module.handle() as usize,
            free_library_offset: free_library_fn_ptr as usize - kernel32_module.handle() as usize,
            get_proc_address_offset: get_proc_address_fn_ptr as usize
                - kernel32_module.handle() as usize,
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into_x86_from_x64")]
    fn _load_inject_help_data_for_process(
        process: ProcessRef<'_>,
    ) -> Result<InjectHelpData, InjectError> {
        // get kernel32 handle of target process (may fail if target process is currently starting and has not loaded kernel32 yet)
        let kernel32_module = retry_with_filter(
            || process.find_module_by_name("kernel32.dll"),
            Option::is_some,
            Duration::from_secs(1),
        )?
        .unwrap();

        // get path of kernel32 used in target process
        let kernel32_path = if process.is_x86()? {
            // We need to manually construct the path to the kernel32.dll used in WOW64 processes.
            let mut wow64_path = Self::wow64_dir()?;
            wow64_path.push("kernel32.dll");
            wow64_path
        } else {
            kernel32_module.path()?
        };

        // load the dll as a pe and extract the fn offsets
        let module_file_buffer = fs::read(kernel32_path)?;
        let pe = PE::parse(&module_file_buffer)?;
        let load_library_export = pe
            .exports
            .iter()
            .find(|export| matches!(export.name, Some("LoadLibraryW")))
            .unwrap();

        let free_library_export = pe
            .exports
            .iter()
            .find(|export| matches!(export.name, Some("FreeLibrary")))
            .unwrap();

        let get_proc_address_export = pe
            .exports
            .iter()
            .find(|export| matches!(export.name, Some("GetProcAddress")))
            .unwrap();

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_export.rva,
            free_library_offset: free_library_export.rva,
            get_proc_address_offset: get_proc_address_export.rva,
        })
    }

    #[cfg(all(target_arch = "x86_64", feature = "into_x86_from_x64"))]
    fn wow64_dir() -> Result<PathBuf, Win32Error> {
        let mut path_buf = MaybeUninit::uninit_array::<MAX_PATH>();
        let path_buf_len: u32 = path_buf.len().try_into().unwrap();
        let result = unsafe { GetSystemWow64DirectoryW(path_buf[0].as_mut_ptr(), path_buf_len) };
        if result == 0 {
            return Err(Win32Error::new());
        }

        let path_len = result as usize;
        let path = unsafe { MaybeUninit::slice_assume_init_ref(&path_buf[..path_len]) };
        Ok(PathBuf::from(U16Str::from_slice(path).to_os_string()))
    }
}
