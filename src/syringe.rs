use fn_ptr::FnPtr;
use iced_x86::{
    code_asm::{
        dword_ptr,
        registers::{gpr32::*, gpr64::*},
        CodeAssembler,
    },
    Code, IcedError,
};
use num_enum::TryFromPrimitive;
use path_absolutize::Absolutize;
use std::{cell::OnceCell, io, mem, path::Path, ptr};
use widestring::{u16cstr, U16CString};
use winapi::shared::{
    minwindef::{BOOL, DWORD, FALSE, HMODULE},
    ntdef::LPCWSTR,
};

use crate::{
    error::{EjectError, ExceptionCode, ExceptionOrIoError, InjectError, LoadInjectHelpDataError},
    process::{
        memory::{RemoteAllocation, RemoteBox, RemoteBoxAllocator},
        BorrowedProcess, BorrowedProcessModule, ModuleHandle, OwnedProcess, Process, ProcessModule,
    },
};

#[cfg(all(target_arch = "x86_64", feature = "into-x86-from-x64"))]
use {
    goblin::pe::PE,
    std::{fs, mem::MaybeUninit, path::PathBuf, time::Duration},
    widestring::U16Str,
    winapi::{shared::minwindef::MAX_PATH, um::wow64apiset::GetSystemWow64DirectoryW},
};

#[cfg(feature = "rpc-core")]
use {
    fn_ptr::UntypedFnPtr,
    winapi::shared::{minwindef::FARPROC, ntdef::LPCSTR},
};

type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FreeLibraryFn = unsafe extern "system" fn(HMODULE) -> BOOL;
type GetLastErrorFn = unsafe extern "system" fn() -> DWORD;
#[cfg(feature = "rpc-core")]
pub(crate) type GetProcAddressFn = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

#[derive(Debug, Clone)]
pub(crate) struct InjectHelpData {
    kernel32_module: ModuleHandle,
    load_library_offset: usize,
    free_library_offset: usize,
    get_last_error_offset: usize,
    #[cfg(feature = "rpc-core")]
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
    #[cfg(feature = "rpc-core")]
    pub fn get_proc_address_fn_ptr(&self) -> GetProcAddressFn {
        unsafe { mem::transmute(self.kernel32_module as usize + self.get_proc_address_offset) }
    }
}

/// An injector that can inject modules (.dll's) into a target process.
///
/// # Example
/// ```no_run
/// use dll_syringe::{Syringe, process::OwnedProcess};
///
/// // find target process by name
/// let target_process = OwnedProcess::find_first_by_name("target_process").unwrap();
///
/// // create a new syringe for the target process
/// let mut syringe = Syringe::for_process(target_process);
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
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "syringe")))]
pub struct Syringe {
    pub(crate) inject_help_data: OnceCell<InjectHelpData>,
    pub(crate) remote_allocator: RemoteBoxAllocator,
    load_library_w_stub: OnceCell<LoadLibraryWStub>,
    #[cfg(feature = "rpc-core")]
    pub(crate) get_proc_address_stub:
        OnceCell<crate::rpc::RemoteProcedureStub<crate::rpc::GetProcAddressParams, UntypedFnPtr>>,
}

const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Syringe>();
};

impl Syringe {
    /// Creates a new syringe for the given target process.
    #[must_use]
    pub fn for_process(process: OwnedProcess) -> Self {
        Self {
            remote_allocator: RemoteBoxAllocator::new(process),
            inject_help_data: OnceCell::new(),
            load_library_w_stub: OnceCell::new(),
            #[cfg(feature = "rpc-core")]
            get_proc_address_stub: OnceCell::new(),
        }
    }

    /// Creates a new syringe for the given suspended target process.
    pub fn for_suspended_process(process: OwnedProcess) -> io::Result<Self> {
        let syringe = Self::for_process(process);

        // If we are injecting into a 'suspended' process, then said process is said to not be fully
        // initialized. This means:
        // - We can't use `EnumProcessModulesEx` and friends.
        // - So we can't locate Kernel32.dll in 32-bit process (from 64-bit process)
        // - And therefore calling LoadLibrary is not possible.

        // Thankfully we can 'initialize' this suspended process without running any end user logic
        // (e.g. a game's entry point) by creating a dummy method and invoking it.
        let ret = Code::Retnq.op_code().op_code();
        debug_assert_eq!(
            Code::Retnw.op_code().op_code(),
            Code::Retnq.op_code().op_code()
        );
        let dummy_fn = syringe.remote_allocator.alloc_and_copy(&ret)?;
        syringe.process().run_remote_thread(
            unsafe { mem::transmute(dummy_fn.as_raw_ptr()) },
            ptr::null_mut::<u8>(),
        )?;

        Ok(syringe)
    }

    /// Returns the target process for this syringe.
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.remote_allocator.process()
    }

    /// Injects the module from the given path into the target process.
    ///
    /// # Limitations
    /// - The target process and the given module need to be of the same bitness.
    /// - If the current process is `x64` the target process can be either `x64` (always available) or `x86` (with the `into_x86_from_x64` feature enabled).
    /// - If the current process is `x86` the target process can only be `x86`.
    pub fn inject(
        &self,
        payload_path: impl AsRef<Path>,
    ) -> Result<BorrowedProcessModule<'_>, InjectError> {
        let load_library_w = self.load_library_w_stub.get_or_try_init(|| {
            let inject_data = self
                .inject_help_data
                .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process()))?;
            LoadLibraryWStub::build(inject_data, &self.remote_allocator)
        })?;

        let module_path = payload_path.as_ref().absolutize()?;
        let wide_module_path =
            U16CString::from_os_str(module_path.as_os_str())?.into_vec_with_nul();
        let remote_wide_module_path = self
            .remote_allocator
            .alloc_and_copy_buf(wide_module_path.as_slice())?;

        let injected_module_handle = load_library_w
            .call(remote_wide_module_path.as_raw_ptr().cast())
            .map_err(|e| match e {
                InjectError::RemoteIo(io) if io.raw_os_error() == Some(193) => {
                    InjectError::ArchitectureMismatch
                }
                _ => e,
            })?;

        let injected_module =
            unsafe { ProcessModule::new_unchecked(injected_module_handle, self.process()) };

        debug_assert_eq!(
            Some(injected_module),
            self.process().find_module_by_path(module_path)?
        );

        Ok(injected_module)
    }

    /// Injects the module from the given path into the target process, if it is not already loaded.
    ///
    /// # Limitations
    /// - The target process and the given module need to be of the same bitness.
    /// - If the current process is `x64` the target process can be either `x64` (always available) or `x86` (with the `into_x86_from_x64` feature enabled).
    /// - If the current process is `x86` the target process can only be `x86`.
    pub fn find_or_inject(
        &self,
        payload_path: impl AsRef<Path>,
    ) -> Result<BorrowedProcessModule<'_>, InjectError> {
        let payload_path = payload_path.as_ref();
        match self.process().find_module_by_path(payload_path) {
            Ok(Some(module)) => Ok(module),
            Ok(None) => self.inject(payload_path),
            Err(err) => Err(err.into()),
        }
    }

    /// Ejects a module from the target process.
    ///
    /// # Panics
    /// This method panics if the given module was not loaded in the target process.
    pub fn eject<'a>(
        &self,
        module: impl Into<BorrowedProcessModule<'a>>,
    ) -> Result<(), EjectError> {
        let module = module.into();
        assert!(
            module.process() == &self.process(),
            "trying to eject a module from a different process"
        );

        let inject_data = self
            .inject_help_data
            .get_or_try_init(|| Self::load_inject_help_data_for_process(self.process()))?;

        if !module.guess_is_loaded() {
            return if self.process().is_alive() {
                Err(EjectError::ModuleInaccessible)
            } else {
                Err(EjectError::ProcessInaccessible)
            };
        }

        let exit_code = self.process().run_remote_thread(
            unsafe { inject_data.get_free_library_fn_ptr().with_output::<u32>().as_safe() },
            module.handle(),
        )?;

        let free_library_result = exit_code as BOOL;

        if free_library_result == FALSE {
            return Err(EjectError::RemoteIo(io::Error::other(
                "failed to eject module from process",
            )));
        }
        if let Ok(exception) = ExceptionCode::try_from_primitive(exit_code) {
            return Err(EjectError::RemoteException(exception));
        }

        debug_assert!(
            !self
                .remote_allocator
                .process()
                .module_handles()?
                .any(|m| m == module.handle()),
            "ejected module survived"
        );

        Ok(())
    }

    pub(crate) fn load_inject_help_data_for_process(
        process: BorrowedProcess<'_>,
    ) -> Result<InjectHelpData, LoadInjectHelpDataError> {
        let is_target_x64 = process.is_x64()?;
        let is_self_x64 = cfg!(target_arch = "x86_64");

        match (is_target_x64, is_self_x64) {
            (true, true) | (false, false) => Self::load_inject_help_data_for_current_target(),
            #[cfg(all(target_arch = "x86_64", feature = "into-x86-from-x64"))]
            (false, true) => Self::_load_inject_help_data_for_process(process),
            _ => Err(LoadInjectHelpDataError::UnsupportedTarget),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn remote_exit_code_to_exception(exit_code: u32) -> Result<u32, ExceptionCode> {
        if exit_code == 0 {
            return Ok(exit_code);
        }

        match ExceptionCode::try_from_primitive(exit_code) {
            Ok(exception) => Err(exception),
            Err(_) => Ok(exit_code),
        }
    }

    pub(crate) fn remote_exit_code_to_error_or_exception(
        exit_code: u32,
    ) -> Result<(), ExceptionOrIoError> {
        if exit_code == 0 {
            return Ok(());
        }

        match ExceptionCode::try_from_primitive(exit_code) {
            Ok(exception) => Err(ExceptionOrIoError::Exception(exception)),
            Err(_) => Err(ExceptionOrIoError::Io(io::Error::from_raw_os_error(
                exit_code as _,
            ))),
        }
    }

    fn load_inject_help_data_for_current_target() -> Result<InjectHelpData, LoadInjectHelpDataError>
    {
        let kernel32_module =
            BorrowedProcessModule::find_local_by_name_or_abs_path_wstr(u16cstr!("kernel32.dll"))?
                .unwrap();

        let load_library_fn_ptr =
            kernel32_module.get_local_procedure_address_cstr(c"LoadLibraryW")?;
        let free_library_fn_ptr =
            kernel32_module.get_local_procedure_address_cstr(c"FreeLibrary")?;
        let get_last_error_fn_ptr =
            kernel32_module.get_local_procedure_address_cstr(c"GetLastError")?;
        #[cfg(feature = "rpc-core")]
        let get_proc_address_fn_ptr =
            kernel32_module.get_local_procedure_address_cstr(c"GetProcAddress")?;

        Ok(InjectHelpData {
            kernel32_module: kernel32_module.handle(),
            load_library_offset: load_library_fn_ptr as usize - kernel32_module.handle() as usize,
            free_library_offset: free_library_fn_ptr as usize - kernel32_module.handle() as usize,
            get_last_error_offset: get_last_error_fn_ptr as usize
                - kernel32_module.handle() as usize,
            #[cfg(feature = "rpc-core")]
            get_proc_address_offset: get_proc_address_fn_ptr as usize
                - kernel32_module.handle() as usize,
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "into-x86-from-x64")]
    fn _load_inject_help_data_for_process(
        process: BorrowedProcess<'_>,
    ) -> Result<InjectHelpData, LoadInjectHelpDataError> {
        // get kernel32 handle of target process (may fail if target process is currently starting and has not loaded kernel32 yet)
        let kernel32_module = process
            .wait_for_module_by_name("kernel32.dll", Duration::from_secs(1))?
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

        #[cfg(feature = "rpc-core")]
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
            #[cfg(feature = "rpc-core")]
            get_proc_address_offset: get_proc_address_export.rva,
        })
    }

    #[cfg(all(target_arch = "x86_64", feature = "into-x86-from-x64"))]
    fn wow64_dir() -> Result<PathBuf, io::Error> {
        let mut path_buf = const { [MaybeUninit::uninit(); MAX_PATH] };
        let path_buf_len: u32 = path_buf.len().try_into().unwrap();
        let result = unsafe { GetSystemWow64DirectoryW(path_buf[0].as_mut_ptr(), path_buf_len) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        let path_len = result as usize;
        let path = unsafe { &path_buf[..path_len].assume_init_ref() };
        Ok(PathBuf::from(U16Str::from_slice(path).to_os_string()))
    }
}

#[derive(Debug)]
struct LoadLibraryWStub {
    code: RemoteAllocation,
    result: RemoteBox<ModuleHandle>,
}

unsafe impl Send for LoadLibraryWStub {}

impl LoadLibraryWStub {
    fn build(
        inject_data: &InjectHelpData,
        remote_allocator: &RemoteBoxAllocator,
    ) -> Result<Self, InjectError> {
        let result = remote_allocator.alloc_uninit::<ModuleHandle>()?;

        let code = if remote_allocator.process().is_x86()? {
            Self::build_code_x86(
                inject_data.get_load_library_fn_ptr(),
                result.as_raw_ptr().cast(),
                inject_data.get_get_last_error(),
            )
            .unwrap()
        } else {
            Self::build_code_x64(
                inject_data.get_load_library_fn_ptr(),
                result.as_raw_ptr().cast(),
                inject_data.get_get_last_error(),
            )
            .unwrap()
        };
        let code = remote_allocator.alloc_and_copy_buf(code.as_slice())?;

        Ok(Self { code, result })
    }

    fn call(&self, remote_wide_module_path: *mut u16) -> Result<ModuleHandle, InjectError> {
        // creating a thread that will call LoadLibraryW with a pointer to payload_path as argument
        let exit_code = self.code.process().run_remote_thread(
            unsafe { mem::transmute(self.code.as_raw_ptr()) },
            remote_wide_module_path,
        )?;

        Syringe::remote_exit_code_to_error_or_exception(exit_code)?;

        let injected_module_handle = self.result.read()?;
        assert!(!injected_module_handle.is_null());

        Ok(injected_module_handle)
    }

    #[allow(dead_code)]
    fn process(&self) -> BorrowedProcess<'_> {
        self.code.process()
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_code_x86(
        load_library_w: LoadLibraryWFn,
        return_buffer: *mut HMODULE,
        get_last_error: GetLastErrorFn,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());
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

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_code_x64(
        load_library_w: LoadLibraryWFn,
        return_buffer: *mut HMODULE,
        get_last_error: GetLastErrorFn,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());

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
