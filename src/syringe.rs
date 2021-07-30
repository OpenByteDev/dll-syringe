use cstr::cstr;
use dispose::defer;
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "into_x86_from_x64")]
use goblin::Object;
use rust_win32error::Win32Error;
use u16cstr::u16cstr;
use std::{
    convert::TryInto,
    fs,
    lazy::OnceCell,
    mem::{self, MaybeUninit},
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};
use widestring::{U16CString, U16Str};
use winapi::{
    shared::{
        minwindef::{BOOL, HMODULE, MAX_PATH},
        ntdef::LPCWSTR,
    },
    um::{
        handleapi::CloseHandle,
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{CreateRemoteThread, GetExitCodeThread},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_FAILED},
        wow64apiset::GetSystemWow64DirectoryW,
    },
};

use crate::{ 
    utils::{retry_with_filter, ForeignProcessWideString}, InjectedModule, ModuleHandle, Process,
    error::{InjectError},
    ProcessModule,
};

type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FreeLibraryFn = unsafe extern "system" fn(HMODULE) -> BOOL;

#[derive(Debug)]
struct InjectHelpData {
    kernel32_module: ModuleHandle,
    load_library_offset: usize,
    free_library_offset: usize,
}

impl InjectHelpData {
    pub fn get_load_library_fn_ptr(&self) -> LoadLibraryWFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.load_library_offset) }
    }
    pub fn get_free_library_fn_ptr(&self) -> FreeLibraryFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.free_library_offset) }
    }
}

#[derive(Default, Debug)]
pub struct Syringe {
    x86_data: OnceCell<InjectHelpData>,
    #[cfg(target_arch = "x86_64")]
    x64_data: OnceCell<InjectHelpData>,
}

impl Syringe {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_inject_help_data_for_process(
        &self,
        process: &Process,
    ) -> Result<&InjectHelpData, InjectError> {
        let is_target_x64 = !process.is_wow64()?;

        #[cfg(target_arch = "x86_64")]
        {
            if is_target_x64 {
                self.x64_data
                    .get_or_try_init(Self::load_inject_help_data_for_current_target)
            } else if cfg!(feature = "into_x86_from_x64") {
                self.x86_data
                    .get_or_try_init(|| Self::load_inject_help_data_for_process(process))
            } else {
                Err(InjectError::UnsupportedTarget)
            }
        }

        #[cfg(target_arch = "x86")]
        {
            if is_target_x64 {
                todo!()
            } else {
                self.x86_data
                    .get_or_try_init(Self::load_inject_help_data_for_current_target)
            }
        }
    }

    pub fn inject<'a>(
        &'a self,
        process: &'a Process,
        payload_path: impl AsRef<Path>,
    ) -> Result<InjectedModule<'a>, InjectError> {
        let inject_data = self.get_inject_help_data_for_process(process)?;

        let module_path = payload_path.as_ref();
        let mut foreign_string = ForeignProcessWideString::allocate_in_process(
            process,
            U16CString::from_os_str(module_path.as_os_str())?,
        )?;

        // creating a thread that will call LoadLibraryA with payload_path_ptr as argument
        let thread_handle = unsafe {
            CreateRemoteThread(
                process.handle(),
                ptr::null_mut(),
                0,
                Some(mem::transmute(inject_data.get_load_library_fn_ptr())),
                foreign_string.as_mut_ptr(),
                0,
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(Win32Error::new().into());
        }

        // ensure handle is closed once we exit this function
        let _h = defer(|| unsafe {
            CloseHandle(thread_handle);
        });

        let reason = unsafe { WaitForSingleObject(thread_handle, INFINITE) };
        if reason == WAIT_FAILED {
            return Err(Win32Error::new().into());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result = unsafe { GetExitCodeThread(thread_handle, exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::new().into());
        }
        assert_ne!(result, STILL_ACTIVE.try_into().unwrap());

        let exit_code = unsafe { exit_code.assume_init() };

        // reinterpret the possibly truncated exit code as a truncated handle to the loaded module
        let truncated_injected_module_handle =
            unsafe { mem::transmute::<usize, ModuleHandle>(exit_code as usize) };
        if truncated_injected_module_handle.is_null() {
            return Err(InjectError::RemoteOperationFailed);
        }

        let injected_module = process.find_module_by_path(module_path)?.unwrap();
        assert_eq!(
            injected_module.handle() as u32,
            truncated_injected_module_handle as u32
        );

        Ok(InjectedModule {
            syringe: self,
            process,
            module: injected_module,
        })
    }

    pub fn eject<'a>(
        &self,
        process: &'a Process,
        module: impl Into<ProcessModule<'a>>,
    ) -> Result<(), InjectError> {
        let inject_data = self.get_inject_help_data_for_process(process)?;
        let module = module.into();

        let thread_handle = unsafe {
            CreateRemoteThread(
                process.handle(),
                ptr::null_mut(),
                0,
                Some(mem::transmute(inject_data.get_free_library_fn_ptr())),
                module.handle() as *mut _,
                0,
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(Win32Error::new().into());
        }

        // ensure handle is closed once we exit this function
        let _h = defer(|| unsafe {
            CloseHandle(thread_handle);
        });

        let reason = unsafe { WaitForSingleObject(thread_handle, INFINITE) };
        if reason == WAIT_FAILED {
            return Err(Win32Error::new().into());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result = unsafe { GetExitCodeThread(thread_handle, exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::new().into());
        }
        assert_ne!(result, STILL_ACTIVE.try_into().unwrap());

        let exit_code = unsafe { exit_code.assume_init() };

        let free_library_result = unsafe { mem::transmute::<u32, BOOL>(exit_code) };
        if free_library_result == 0 {
            return Err(InjectError::RemoteOperationFailed);
        }

        assert!(!process
            .get_module_handles()?
            .as_ref()
            .contains(&module.handle()));

        Ok(())
    }

    fn load_inject_help_data_for_current_target() -> Result<InjectHelpData, InjectError> {
        let kernel32_module = ProcessModule::__get_local_from_name_or_abs_path(u16cstr!("kernel32.dll"))?.unwrap(); // TODO: avoid alloc
        let load_library_fn_ptr = kernel32_module.__get_procedure(cstr!("LoadLibraryW"))?;
        let free_library_fn_ptr = kernel32_module.__get_procedure(cstr!("FreeLibrary"))?;

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_fn_ptr as usize - kernel32_module.handle() as usize,
            free_library_offset: free_library_fn_ptr as usize - kernel32_module.handle() as usize,
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into_x86_from_x64")]
    fn load_inject_help_data_for_process(process: &Process) -> Result<InjectHelpData, InjectError> {
        // get kernel32 handle of target process
        let kernel32_module = retry_with_filter(
            || process.find_module_by_name("kernel32.dll"),
            |o| o.is_some(),
            Duration::from_secs(1),
        )?
        .unwrap();

        // get path of kernel32 used in target process
        let kernel32_path = if process.is_wow64()? {
            // we need to manually construct the path to the kernel32.dll used in WOW64 processes
            let mut wow64_path = Self::get_wow64_dir()?;
            wow64_path.push("kernel32.dll");
            wow64_path
        } else {
            kernel32_module.get_path()?
        };

        // load the dll as a pe and extract the fn offsets
        let module_file_buffer = fs::read(kernel32_path)?;
        if let Object::PE(pe) = Object::parse(&module_file_buffer)? {
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

            Ok(InjectHelpData {
                kernel32_module: kernel32_module.handle(),
                load_library_offset: load_library_export.rva,
                free_library_offset: free_library_export.rva,
            })
        } else {
            unreachable!()
        }
    }

    fn get_wow64_dir() -> Result<PathBuf, Win32Error> {
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
