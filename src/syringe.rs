use cstr::cstr;
use get_last_error::Win32Error;
use iced_x86::{code_asm::*, IcedError};
use num_enum::TryFromPrimitive;
use path_absolutize::Absolutize;
use std::{ffi::c_void, io, lazy::OnceCell, mem, path::Path};
use u16cstr::u16cstr;
use widestring::U16CString;
use winapi::shared::{
    minwindef::{BOOL, DWORD, FALSE, HMODULE},
    ntdef::LPCWSTR,
};

use crate::{
    error::{ExceptionCode, SyringeError},
    process_memory::{RemoteBox, RemoteBoxAllocator},
    ModuleHandle, ProcessModule, ProcessRef,
};

#[cfg(all(target_arch = "x86_64", feature = "into_x86_from_x64"))]
use {
    crate::utils::retry_with_filter,
    goblin::pe::PE,
    std::{convert::TryInto, fs, mem::MaybeUninit, path::PathBuf, time::Duration},
    widestring::U16Str,
    winapi::{shared::minwindef::MAX_PATH, um::wow64apiset::GetSystemWow64DirectoryW},
};

#[cfg(feature = "remote_procedure")]
use winapi::shared::{minwindef::FARPROC, ntdef::LPCSTR};

type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FreeLibraryFn = unsafe extern "system" fn(HMODULE) -> BOOL;
type GetLastErrorFn = unsafe extern "system" fn() -> DWORD;
#[cfg(feature = "remote_procedure")]
type GetProcAddressFn = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

#[derive(Debug, Clone)]
pub(crate) struct InjectHelpData {
    kernel32_module: ModuleHandle,
    load_library_offset: usize,
    free_library_offset: usize,
    get_last_error_offset: usize,
    #[cfg(feature = "remote_procedure")]
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
    pub fn get_get_last_error(&self) -> GetLastErrorFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.get_last_error_offset) }
    }
    #[cfg(feature = "remote_procedure")]
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
    load_library_w_stub: OnceCell<LoadLibraryWStub<'a>>,
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
            load_library_w_stub: OnceCell::new(),
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
    ) -> Result<ProcessModule<'a>, SyringeError> {
        self.load_library_w_stub.get_or_try_init(|| {
            let inject_data = self
                .inject_help_data
                .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process))?;
            LoadLibraryWStub::build(inject_data, &mut self.remote_allocator)
        })?;
        let load_library_w = self.load_library_w_stub.get_mut().unwrap();

        let module_path = payload_path.as_ref().absolutize()?;
        let wide_module_path =
            U16CString::from_os_str(module_path.as_os_str())?.into_vec_with_nul();
        let mut remote_wide_module_path = self
            .remote_allocator
            .alloc_and_copy(wide_module_path.as_slice())?;

        let injected_module_handle =
            load_library_w.call(remote_wide_module_path.as_raw_ptr().cast())?;
        let injected_module =
            unsafe { ProcessModule::new_unchecked(injected_module_handle, self.process) };

        debug_assert_eq!(
            injected_module,
            self.process.find_module_by_path(module_path)?.unwrap()
        );

        Ok(injected_module)
    }

    /// Ejects a previously injected module from its target process.
    pub fn eject(&self, module: ProcessModule<'_>) -> Result<(), SyringeError> {
        assert!(
            module.process() == self.process,
            "trying to eject a module from a different process"
        );

        let inject_data = self
            .inject_help_data
            .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process))?;

        let exit_code = self.process.run_remote_thread(
            unsafe { mem::transmute(inject_data.get_free_library_fn_ptr()) },
            module.handle().cast(),
        )?;

        let free_library_result = exit_code as BOOL;

        if free_library_result == FALSE {
            return Err(SyringeError::RemoteIo(io::Error::new(
                io::ErrorKind::Other,
                "failed to eject module from process",
            )));
        }
        if let Ok(exception) = ExceptionCode::try_from_primitive(exit_code) {
            return Err(SyringeError::RemoteException(exception));
        }

        debug_assert!(
            !self
                .process
                .module_handles()?
                .as_ref()
                .contains(&module.handle()),
            "ejected module survived"
        );

        Ok(())
    }

    pub(crate) fn load_inject_help_data_for_process(
        process: ProcessRef<'_>,
    ) -> Result<InjectHelpData, SyringeError> {
        let is_target_x64 = process.is_x64()?;
        let is_self_x64 = cfg!(target_arch = "x86_64");

        match (is_target_x64, is_self_x64) {
            (true, true) | (false, false) => Self::load_inject_help_data_for_current_target(),
            #[cfg(all(target_arch = "x86_64", feature = "into_x86_from_x64"))]
            (false, true) => Self::_load_inject_help_data_for_process(process),
            _ => Err(SyringeError::UnsupportedTarget),
        }
    }

    pub(crate) fn remote_exit_code_to_exception(exit_code: u32) -> Result<(), SyringeError> {
        if exit_code == 0 {
            return Ok(());
        }

        match ExceptionCode::try_from_primitive(exit_code) {
            Ok(exception) => Err(SyringeError::RemoteException(exception)),
            Err(_) => Err(SyringeError::RemoteIo(io::Error::new(
                io::ErrorKind::Other,
                "unknown remote process error",
            ))),
        }
    }

    pub(crate) fn remote_exit_code_to_error_or_exception(
        exit_code: u32,
    ) -> Result<(), SyringeError> {
        if exit_code == 0 {
            return Ok(());
        }

        match ExceptionCode::try_from_primitive(exit_code) {
            Ok(exception) => Err(SyringeError::RemoteException(exception)),
            Err(_) => Err(SyringeError::RemoteIo(Win32Error::new(exit_code).into())),
        }
    }

    fn load_inject_help_data_for_current_target() -> Result<InjectHelpData, SyringeError> {
        let kernel32_module =
            ProcessModule::__find_local_by_name_or_abs_path(u16cstr!("kernel32.dll"))?.unwrap();

        let load_library_fn_ptr = kernel32_module.__get_local_procedure(cstr!("LoadLibraryW"))?;
        let free_library_fn_ptr = kernel32_module.__get_local_procedure(cstr!("FreeLibrary"))?;
        let get_last_error_fn_ptr = kernel32_module.__get_local_procedure(cstr!("GetLastError"))?;
        #[cfg(feature = "remote_procedure")]
        let get_proc_address_fn_ptr =
            kernel32_module.__get_local_procedure(cstr!("GetProcAddress"))?;

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_fn_ptr as usize - kernel32_module.handle() as usize,
            free_library_offset: free_library_fn_ptr as usize - kernel32_module.handle() as usize,
            get_last_error_offset: get_last_error_fn_ptr as usize
                - kernel32_module.handle() as usize,
            #[cfg(feature = "remote_procedure")]
            get_proc_address_offset: get_proc_address_fn_ptr as usize
                - kernel32_module.handle() as usize,
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into_x86_from_x64")]
    fn _load_inject_help_data_for_process(
        process: ProcessRef<'_>,
    ) -> Result<InjectHelpData, SyringeError> {
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

        let get_last_error_export = pe
            .exports
            .iter()
            .find(|export| matches!(export.name, Some("GetLastError")))
            .unwrap();

        #[cfg(feature = "remote_procedure")]
        let get_proc_address_export = pe
            .exports
            .iter()
            .find(|export| matches!(export.name, Some("GetProcAddress")))
            .unwrap();

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_export.rva,
            free_library_offset: free_library_export.rva,
            get_last_error_offset: get_last_error_export.rva,
            #[cfg(feature = "remote_procedure")]
            get_proc_address_offset: get_proc_address_export.rva,
        })
    }

    #[cfg(all(target_arch = "x86_64", feature = "into_x86_from_x64"))]
    fn wow64_dir() -> Result<PathBuf, Win32Error> {
        let mut path_buf = MaybeUninit::uninit_array::<MAX_PATH>();
        let path_buf_len: u32 = path_buf.len().try_into().unwrap();
        let result = unsafe { GetSystemWow64DirectoryW(path_buf[0].as_mut_ptr(), path_buf_len) };
        if result == 0 {
            return Err(Win32Error::get_last_error());
        }

        let path_len = result as usize;
        let path = unsafe { MaybeUninit::slice_assume_init_ref(&path_buf[..path_len]) };
        Ok(PathBuf::from(U16Str::from_slice(path).to_os_string()))
    }
}

#[derive(Debug)]
struct LoadLibraryWStub<'a> {
    code: RemoteBox<'a, [u8]>,
    result: RemoteBox<'a, ModuleHandle>,
}

impl<'a> LoadLibraryWStub<'a> {
    fn build(
        inject_data: &InjectHelpData,
        remote_allocator: &mut RemoteBoxAllocator<'a>,
    ) -> Result<Self, SyringeError> {
        let mut result = remote_allocator.alloc_uninit::<ModuleHandle>()?;

        let code = if remote_allocator.process().is_x86()? {
            Self::build_code_x86(
                inject_data.get_load_library_fn_ptr() as *const _,
                result.as_raw_ptr().cast(),
                inject_data.get_get_last_error() as *const _,
            )
            .unwrap()
        } else {
            Self::build_code_x64(
                inject_data.get_load_library_fn_ptr() as *const _,
                result.as_raw_ptr().cast(),
                inject_data.get_get_last_error() as *const _,
            )
            .unwrap()
        };
        let code = remote_allocator.alloc_and_copy(code.as_slice())?;

        Ok(Self { code, result })
    }

    fn call(&mut self, remote_wide_module_path: *mut u16) -> Result<ModuleHandle, SyringeError> {
        // creating a thread that will call LoadLibraryW with a pointer to payload_path as argument
        let exit_code = self.process().run_remote_thread(
            unsafe { mem::transmute(self.code.as_raw_ptr()) },
            remote_wide_module_path.cast(),
        )?;

        Syringe::remote_exit_code_to_error_or_exception(exit_code)?;

        let injected_module_handle = self.result.read()?;
        assert!(!injected_module_handle.is_null());

        Ok(injected_module_handle)
    }

    fn process(&self) -> ProcessRef<'a> {
        self.code.process()
    }

    fn build_code_x86(
        load_library_w: *const c_void,
        return_buffer: *mut c_void,
        get_last_error: *const c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!load_library_w.is_null());
        assert!(!return_buffer.is_null());
        assert!(!get_last_error.is_null());
        assert_eq!(load_library_w as u32 as usize, load_library_w as usize);
        assert_eq!(return_buffer as u32 as usize, return_buffer as usize);
        assert_eq!(get_last_error as u32 as usize, get_last_error as usize);

        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // CreateRemoteThread lpParameter
        asm.push(eax)?; // lpLibFileName
        asm.mov(eax, load_library_w as u32)?;
        asm.call(eax)?;
        asm.mov(dword_ptr(return_buffer as u32), eax)?;
        // asm.mov(eax, 0)?;
        let mut label = asm.create_label();
        asm.test(eax, eax)?;
        asm.mov(eax, 0)?;
        asm.jnz(label)?;
        asm.mov(eax, get_last_error as u32)?;
        asm.call(eax)?; // return 0
        asm.set_label(&mut label)?;
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "LoadLibraryW x86 stub is not location independent"
        );

        Ok(code)
    }

    fn build_code_x64(
        load_library_w: *const c_void,
        return_buffer: *mut c_void,
        get_last_error: *const c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!load_library_w.is_null());
        assert!(!return_buffer.is_null());
        assert!(!get_last_error.is_null());

        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space

        // arg already in rcx
        asm.mov(rax, load_library_w as u64)?;
        asm.call(rax)?;
        asm.mov(dword_ptr(return_buffer as u64), rax)?; // move result to buffer

        let mut label = asm.create_label();
        asm.test(rax, rax)?;
        asm.mov(rax, 0u64)?;
        asm.jnz(label)?;
        asm.mov(rax, get_last_error as u64)?;
        asm.call(rax)?; // return 0
        asm.set_label(&mut label)?;

        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "LoadLibraryW x64 stub is not location independent"
        );

        Ok(code)
    }
}
