use cstr::cstr;
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "into_x86_from_x64")]
use goblin::pe::PE;
#[cfg(feature = "call_remote_procedure")]
use iced_x86::{code_asm::*, IcedError};
use path_absolutize::Absolutize;
use rust_win32error::Win32Error;
use std::{
    convert::TryInto,
    ffi::{c_void, CString},
    fs,
    mem::{self, MaybeUninit},
    os::windows::prelude::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr,
    time::Duration,
};
use u16cstr::u16cstr;
use widestring::{U16CString, U16Str};
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPVOID, MAX_PATH},
        ntdef::{LPCSTR, LPCWSTR},
    },
    um::{
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{CreateRemoteThread, GetExitCodeThread},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_FAILED},
        wow64apiset::GetSystemWow64DirectoryW,
    },
};

use crate::{
    error::InjectError,
    utils::{retry_with_filter, SharedMemory},
    ModuleHandle, ProcessModule, ProcessRef,
};

type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FreeLibraryFn = unsafe extern "system" fn(HMODULE) -> BOOL;
type GetProcAddressFn = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

#[derive(Debug, Clone)]
struct InjectHelpData {
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
/// // create new syringe (reuse for better performance)
/// let syringe = Syringe::new();
///
/// // inject the payload into the target process
/// let injected_payload = syringe.inject(&target_process, "injection_payload.dll").unwrap();
///
/// // do something else
///
/// // eject the payload from the target (optional)
/// syringe.eject(injected_payload).unwrap();
/// ```
#[derive(Default, Debug, Clone)]
pub struct Syringe {
    #[cfg(not(feature = "sync_send_syringe"))]
    x86_data: std::lazy::OnceCell<InjectHelpData>,
    #[cfg(all(not(feature = "sync_send_syringe"), target_arch = "x86_64"))]
    x64_data: std::lazy::OnceCell<InjectHelpData>,

    #[cfg(feature = "sync_send_syringe")]
    x86_data: std::lazy::SyncOnceCell<InjectHelpData>,
    #[cfg(all(feature = "sync_send_syringe", target_arch = "x86_64"))]
    x64_data: std::lazy::SyncOnceCell<InjectHelpData>,
}

impl Syringe {
    /// Creates a new syringe.
    /// This operation is cheap as internal state is initialized lazily.
    pub fn new() -> Self {
        Self::default()
    }

    fn get_inject_help_data_for_process(
        &self,
        process: ProcessRef,
    ) -> Result<&InjectHelpData, InjectError> {
        let is_target_x64 = process.is_x64()?;

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
                Err(InjectError::UnsupportedTarget)
            } else {
                self.x86_data
                    .get_or_try_init(Self::load_inject_help_data_for_current_target)
            }
        }
    }

    /// Inject the module at the given path into the given process.
    ///
    /// # Limitations
    /// - The target process and the given module need to be of the same bitness.
    /// - If the current process is `x64` the target process can be either `x64` (always available) or `x86` (with the `into_x86_from_x64` feature enabled).
    /// - If the current process is `x86` the target process can only be `x86`.
    pub fn inject<'a>(
        &self,
        process: impl Into<ProcessRef<'a>>,
        payload_path: impl AsRef<Path>,
    ) -> Result<ProcessModule<'a>, InjectError> {
        let process = process.into();
        let inject_data = self.get_inject_help_data_for_process(process)?;
        let module_path = payload_path.as_ref().absolutize()?;

        let wide_module_path =
            U16CString::from_os_str(module_path.as_os_str())?.into_vec_with_nul();
        let module_path_buf = SharedMemory::allocate_struct(process, wide_module_path.as_slice())?;

        // creating a thread that will call LoadLibraryW with a pointer to payload_path as argument
        let exit_code = Self::run_remote_thread(
            process,
            unsafe { mem::transmute(inject_data.get_load_library_fn_ptr()) },
            module_path_buf.as_mut_ptr().cast(),
        )?;

        // reinterpret the possibly truncated exit code as a truncated handle to the loaded module
        let truncated_injected_module_handle = exit_code as ModuleHandle;
        if truncated_injected_module_handle.is_null() {
            return Err(InjectError::RemoteOperationFailed);
        }

        let injected_module = process.find_module_by_path(module_path)?.unwrap();
        assert_eq!(
            injected_module.handle() as u32,
            truncated_injected_module_handle as u32
        );

        Ok(injected_module)
    }

    #[cfg(feature = "call_remote_procedure")]
    /// Load the address of the given function from the given module in the remote process.
    pub fn get_procedure_address(
        &self,
        module: ProcessModule,
        name: impl AsRef<str>,
    ) -> Result<*const c_void, InjectError> {
        let process = module.process();
        let name = name.as_ref();

        let remote_get_proc_address = self
            .get_inject_help_data_for_process(process)?
            .get_proc_address_fn_ptr();

        // Allocate memory in remote process to store the parameter and the return value.
        // TODO: store in a single reusable buffer.
        let get_proc_address_ptr_mem =
            SharedMemory::allocate_struct(process, &remote_get_proc_address)?;
        let return_value_mem = SharedMemory::allocate_uninit_struct::<FARPROC>(process)?;
        let name_mem = SharedMemory::allocate_struct(
            process,
            CString::new(name).unwrap().as_bytes_with_nul(),
        )?;
        let param_mem = SharedMemory::allocate_struct(
            process,
            &GetProcAddressParams {
                module_handle: module.handle() as u64,
                name: name_mem.as_ptr() as u64,
            },
        )?;

        // Allocate memory in remote process and build a method stub.
        let code_mem = SharedMemory::allocate_code(process, 4096)?;
        let code = if process.is_x86()? {
            Syringe::build_get_proc_address_x86(
                code_mem.as_ptr().cast(),
                get_proc_address_ptr_mem.as_ptr().cast(),
                return_value_mem.as_mut_ptr().cast(),
            )
            .unwrap()
        } else {
            assert!(process.is_x64().unwrap_or(false));
            Syringe::build_get_proc_address_x64(
                code_mem.as_ptr().cast(),
                get_proc_address_ptr_mem.as_ptr().cast(),
                return_value_mem.as_mut_ptr().cast(),
            )
            .unwrap()
        };
        code_mem.write(0, &code)?;
        code_mem.flush_instruction_cache()?;

        let exit_code = Self::run_remote_thread(
            process,
            unsafe { mem::transmute(code_mem.as_mut_ptr()) },
            param_mem.as_mut_ptr().cast(),
        )?;
        if exit_code != 0u32 {
            return Err(InjectError::RemoteOperationFailed);
        }

        let return_value = unsafe { return_value_mem.read_struct::<FARPROC>(0) }?;
        Ok(return_value.cast())
    }

    #[cfg(feature = "call_remote_procedure")]
    /// Calls the function pointer retrieved using [Syringe::get_procedure_address] in the remote process.
    /// The target function has to have the following signature: `extern "system" fn(parameter: *const P, result: *mut R)`.
    ///
    /// # Safety
    /// The caller has to ensure that the given function pointer is valid and that it points to a function in the target process with the correct signature.
    pub unsafe fn call_procedure<'a, R, P>(
        &self,
        process: impl Into<ProcessRef<'a>>,
        procedure: *const c_void,
        parameter: &P,
    ) -> Result<R, InjectError> {
        let process = process.into();

        // Allocate memory in remote process to store the parameter, the return value and the method stub.
        // TODO: store in a single reusable buffer.
        let return_value_mem = SharedMemory::allocate_uninit_struct::<R>(process)?;
        let param_mem = SharedMemory::allocate_struct(process, parameter)?;
        let code_mem = SharedMemory::allocate_code(process, 4096)?;

        let code = if process.is_x86()? {
            Syringe::build_call_procedure_x86(
                code_mem.as_ptr().cast(),
                procedure,
                return_value_mem.as_mut_ptr().cast(),
            )
            .unwrap()
        } else {
            assert!(process.is_x64().unwrap_or(false));
            Syringe::build_call_procedure_x64(
                code_mem.as_ptr().cast(),
                procedure,
                return_value_mem.as_mut_ptr().cast(),
            )
            .unwrap()
        };
        code_mem.write(0, &code)?;
        code_mem.flush_instruction_cache()?;

        let exit_code = Self::run_remote_thread(
            process,
            unsafe { mem::transmute(code_mem.as_mut_ptr()) },
            param_mem.as_mut_ptr().cast(),
        )?;
        if exit_code != 0u32 {
            return Err(InjectError::RemoteOperationFailed);
        }

        Ok(unsafe { return_value_mem.read_struct::<R>(0)? })
    }

    #[cfg(feature = "call_remote_procedure")]
    /// Calls the function specified by `procedure` retrieved using [Syringe::get_procedure_address] in the remote process.
    /// The target function has to have the following signature: `extern "system" fn(*mut c_void) -> u32`.
    ///
    /// # Note
    /// Pointers to memory in the current process will not be accessible from the remote process.
    ///
    /// # Safety
    /// The caller has to ensure that the given function pointer is valid and that it points to a function in the target process with the correct signature.
    pub unsafe fn call_procedure_fast<'a>(
        &self,
        process: impl Into<ProcessRef<'a>>,
        procedure: *const c_void,
        parameter: *mut c_void,
    ) -> Result<u32, Win32Error> {
        Self::run_remote_thread(
            process.into(),
            unsafe { mem::transmute(procedure) },
            parameter,
        )
    }

    fn run_remote_thread(
        process: ProcessRef,
        remote_fn: extern "system" fn(LPVOID) -> DWORD,
        parameter: LPVOID,
    ) -> Result<u32, Win32Error> {
        // create a remote thread that will call LoadLibraryW with payload_path as its argument.
        let thread_handle = unsafe {
            CreateRemoteThread(
                process.handle(),
                ptr::null_mut(),
                0,
                Some(remote_fn),
                parameter,
                0, // RUN_IMMEDIATELY
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(Win32Error::new());
        }
        // ensure the handle is closed once we exit this function
        let thread_handle = unsafe { OwnedHandle::from_raw_handle(thread_handle) };

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(Win32Error::new());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
        if result == 0 {
            return Err(Win32Error::new());
        }
        assert_ne!(result, STILL_ACTIVE.try_into().unwrap());

        Ok(unsafe { exit_code.assume_init() })
    }

    #[cfg(feature = "call_remote_procedure")]
    fn build_call_procedure_x86(
        base_address: *const c_void,
        real_address: *const c_void,
        return_buffer_address: *mut c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!base_address.is_null());
        assert!(!real_address.is_null());
        assert!(!return_buffer_address.is_null());

        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // load arg ptr (lpParameter) from stack
        asm.push(return_buffer_address as u32)?; // push result ptr onto stack
        asm.push(eax)?; // push arg ptr onto stack
        asm.mov(eax, real_address as u32)?; // load address of target function
        asm.call(eax)?; // call real_address
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        asm.assemble(base_address as u32 as u64)
    }

    #[cfg(feature = "call_remote_procedure")]
    fn build_call_procedure_x64(
        base_address: *const c_void,
        real_address: *const c_void,
        return_buffer_address: *mut c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!base_address.is_null());
        assert!(!real_address.is_null());
        assert!(!return_buffer_address.is_null());

        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space
        asm.mov(rdx, return_buffer_address as u64)?; // result ptr
        asm.mov(rcx, rcx)?; // arg ptr
        asm.mov(rax, real_address as u64)?;
        asm.call(rax)?;
        asm.mov(rax, 0u64)?; // return 0
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.mov(rax, 0u64)?; // return 0
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        asm.assemble(base_address as u32 as u64)
    }

    #[cfg(feature = "call_remote_procedure")]
    fn build_get_proc_address_x86(
        base_address: *const c_void,
        real_address: *const c_void,
        return_buffer_address: *mut c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!base_address.is_null());
        assert!(!real_address.is_null());
        assert!(!return_buffer_address.is_null());

        // assembly code from https://github.com/Reloaded-Project/Reloaded.Injector/blob/77a9a87392cc75fa087d7004e8cdef054e880428/Source/Reloaded.Injector/Shellcode.cs#L159
        // mov eax, dword [esp + 4]         // CreateRemoteThread lpParameter
        // push dword [eax + 8]             // lpProcName
        // push dword [eax + 0]             // hModule
        // call dword [dword GetProcAddress]
        // mov dword [dword ReturnAddress], eax
        // ret 4                           // Restore stack ptr. (Callee cleanup)
        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // CreateRemoteThread lpParameter
        asm.push(dword_ptr(eax + 8))?; // lpProcName
        asm.push(dword_ptr(eax + 0))?; // hModule
        asm.call(dword_ptr(real_address as u32))?;
        asm.mov(dword_ptr(return_buffer_address as u32), eax)?;
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        asm.assemble(base_address as u32 as u64)
    }

    #[cfg(feature = "call_remote_procedure")]
    fn build_get_proc_address_x64(
        base_address: *const c_void,
        real_address: *const c_void,
        return_buffer_address: *mut c_void,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!base_address.is_null());
        assert!(!real_address.is_null());
        assert!(!return_buffer_address.is_null());

        // assembly code from https://github.com/Reloaded-Project/Reloaded.Injector/blob/77a9a87392cc75fa087d7004e8cdef054e880428/Source/Reloaded.Injector/Shellcode.cs#L188
        //                                      // CreateRemoteThread lpParameter @ ECX
        // sub rsp, 40                          // Re-align stack to 16 byte boundary +32 shadow space
        // mov rdx, qword [qword rcx + 8]       // lpProcName
        // mov rcx, qword [qword rcx + 0]       // hModule
        // call qword [qword GetProcAddress]    // [replaced with indirect call]
        // mov qword [qword ReturnAddress], rax
        // add rsp, 40                          // Re-align stack to 16 byte boundary + shadow space.
        // ret
        let mut asm = CodeAssembler::new(64).unwrap();

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space
        asm.mov(rdx, qword_ptr(rcx + 8))?; // lpProcName
        asm.mov(rcx, qword_ptr(rcx + 0))?; // hModule
        asm.mov(rax, qword_ptr(real_address as u64))?;
        asm.call(rax)?;
        asm.mov(qword_ptr(return_buffer_address as u64), rax)?;
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.mov(rax, 0u64)?; // return 0
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        asm.assemble(base_address as u64)
    }

    /// Ejects a previously injected module from its target process.
    pub fn eject(&self, module: ProcessModule) -> Result<(), InjectError> {
        let process = module.process();
        let inject_data = self.get_inject_help_data_for_process(module.process())?;

        let thread_handle = unsafe {
            CreateRemoteThread(
                process.handle(),
                ptr::null_mut(),
                0,
                Some(mem::transmute(inject_data.get_free_library_fn_ptr())),
                module.handle().cast(),
                0,
                ptr::null_mut(),
            )
        };
        if thread_handle.is_null() {
            return Err(Win32Error::new().into());
        }
        // ensure handle is closed once we exit this function
        let thread_handle = unsafe { OwnedHandle::from_raw_handle(thread_handle) };

        let reason = unsafe { WaitForSingleObject(thread_handle.as_raw_handle(), INFINITE) };
        if reason == WAIT_FAILED {
            return Err(Win32Error::new().into());
        }

        let mut exit_code = MaybeUninit::uninit();
        let result =
            unsafe { GetExitCodeThread(thread_handle.as_raw_handle(), exit_code.as_mut_ptr()) };
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
            .module_handles()?
            .as_ref()
            .contains(&module.handle()));

        Ok(())
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
    fn load_inject_help_data_for_process(
        process: ProcessRef,
    ) -> Result<InjectHelpData, InjectError> {
        // get kernel32 handle of target process
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

#[cfg(all(test, feature = "sync_send_syringe"))]
mod tests {
    #[test]
    fn syringe_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<super::Syringe>();
    }

    #[test]
    fn syringe_is_sync() {
        fn assert_sync<T: Send>() {}
        assert_sync::<super::Syringe>();
    }
}

#[cfg(feature = "call_remote_procedure")]
#[repr(C)]
struct GetProcAddressParams {
    module_handle: u64,
    name: u64,
}
