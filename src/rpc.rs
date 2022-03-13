use iced_x86::{code_asm::*, IcedError};
use serde::{de::DeserializeOwned, Serialize};

use std::{
    ffi::CString,
    mem,
    ptr::{self, NonNull},
};

use crate::{
    error::{RawRpcError, RpcError, SyringeError},
    function::{FunctionPtr, RawFunctionPtr},
    process::{
        memory::{ProcessMemoryBuffer, RemoteAllocation, RemoteBox, RemoteBoxAllocator},
        BorrowedProcess, BorrowedProcessModule, Process,
    },
    ArgAndResultBufInfo, GetProcAddressFn, Syringe,
};

#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc")))]
impl Syringe {
    /// Loads an exported function from the given module from the target process.
    /// The function does not have to be from an injected module.
    /// If the module is not loaded in the target process `Ok(None)` is returned.
    pub fn get_procedure<F: FunctionPtr>(
        &self,
        module: BorrowedProcessModule<'_>,
        name: &str,
    ) -> Result<Option<RemoteProcedure<F>>, SyringeError>
    where
        for<'r> F::RefArgs<'r>: Serialize,
        F::Output: DeserializeOwned,
    {
        match self.get_procedure_address(module, name) {
            Ok(Some(procedure)) => Ok(Some(RemoteProcedure::new(
                unsafe { F::from_ptr(procedure) },
                self.remote_allocator.clone(),
            ))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Load the address of the given function from the given module in the remote process.
    /// If the module is not loaded in the target process `Ok(None)` is returned.
    pub fn get_procedure_address(
        &self,
        module: BorrowedProcessModule<'_>,
        name: impl AsRef<str>,
    ) -> Result<Option<RawFunctionPtr>, SyringeError> {
        if module.process() != &self.remote_allocator.process() {
            return Ok(None);
        }

        let stub = self.build_get_proc_address_stub()?;
        let name = name.as_ref();
        let name = self
            .remote_allocator
            .alloc_and_copy_buf(CString::new(name).unwrap().as_bytes_with_nul())?;
        stub.parameter.write(&GetProcAddressParams {
            module_handle: module.handle() as u64,
            name: name.as_raw_ptr() as u64,
        })?;

        // clear the result
        stub.result.write(&ptr::null_mut())?;

        let exit_code = self.remote_allocator.process().run_remote_thread(
            unsafe { mem::transmute(stub.code.as_raw_ptr()) },
            stub.parameter.as_raw_ptr(),
        )?;
        Syringe::remote_exit_code_to_exception(exit_code)?;

        Ok(NonNull::new(stub.result.read()?).map(|p| p.as_ptr()))
    }

    fn build_get_proc_address_stub(
        &self,
    ) -> Result<&RemoteProcedureStub<GetProcAddressParams, RawFunctionPtr>, SyringeError> {
        self.get_proc_address_stub.get_or_try_init(|| {
            let inject_data = self.inject_help_data.get_or_try_init(|| {
                Self::load_inject_help_data_for_process(self.remote_allocator.process())
            })?;

            let remote_get_proc_address = inject_data.get_proc_address_fn_ptr();

            let parameter = self
                .remote_allocator
                .alloc_uninit::<GetProcAddressParams>()?;
            let result = self.remote_allocator.alloc_uninit::<RawFunctionPtr>()?;

            // Allocate memory in remote process and build a method stub.
            let code = if self.remote_allocator.process().is_x86()? {
                Syringe::build_get_proc_address_x86(
                    remote_get_proc_address,
                    result.as_ptr().as_ptr(),
                )
                .unwrap()
            } else {
                Syringe::build_get_proc_address_x64(
                    remote_get_proc_address,
                    result.as_ptr().as_ptr(),
                )
                .unwrap()
            };
            let function_stub = self.remote_allocator.alloc_and_copy_buf(code.as_slice())?;
            function_stub.memory().flush_instruction_cache()?;

            Ok(RemoteProcedureStub {
                code: function_stub,
                parameter,
                result,
            })
        })
    }

    /*
    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_procedure_x86<F: FunctionPtr>(
        procedure: F,
        return_buffer: *mut F::Output,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());
        assert_eq!(
            procedure.as_ptr() as u32 as usize,
            procedure.as_ptr() as usize
        );
        assert_eq!(return_buffer as u32 as usize, return_buffer as usize);

        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // load arg ptr (lpParameter) from stack
        asm.push(return_buffer as u32)?; // push result ptr onto stack
        asm.push(eax)?; // push arg ptr onto stack
        asm.mov(eax, procedure.as_ptr() as u32)?; // load address of target function
        asm.call(eax)?; // call real_address
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "CallProcedure x86 stub is not location independent"
        );

        Ok(code)
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_procedure_x64<F: FunctionPtr>(
        procedure: F,
        return_buffer: *mut F::Output,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());

        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space
        asm.mov(rdx, return_buffer as u64)?; // result ptr
        asm.mov(rcx, rcx)?; // arg ptr
        asm.mov(rax, procedure.as_ptr() as u64)?;
        asm.call(rax)?;
        asm.mov(rax, 0u64)?; // return 0
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.mov(rax, 0u64)?; // return 0
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "CallProcedure x64 stub is not location independent"
        );

        Ok(code)
    }
    */

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_get_proc_address_x86(
        get_proc_address: GetProcAddressFn,
        return_buffer: *mut RawFunctionPtr,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());
        assert_eq!(get_proc_address as u32 as usize, get_proc_address as usize);
        assert_eq!(return_buffer as u32 as usize, return_buffer as usize);

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
        asm.mov(eax, get_proc_address.as_ptr() as u32)?;
        asm.call(eax)?;
        asm.mov(dword_ptr(return_buffer as u32), eax)?;
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "GetProcAddress x86 stub is not location independent"
        );

        Ok(code)
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_get_proc_address_x64(
        get_proc_address: GetProcAddressFn,
        return_buffer: *mut RawFunctionPtr,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!return_buffer.is_null());

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
        asm.mov(rax, get_proc_address.as_ptr() as u64)?;
        asm.call(rax)?;
        asm.mov(qword_ptr(return_buffer as u64), rax)?;
        asm.mov(rax, 0u64)?; // return 0
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "GetProcAddress x64 stub is not location independent"
        );

        Ok(code)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct GetProcAddressParams {
    module_handle: u64,
    name: u64,
}

/// A struct representing a procedure from a module of a remote process.
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc")))]
#[derive(Debug)]
pub struct RemoteProcedure<F: FunctionPtr> {
    ptr: F,
    remote_allocator: RemoteBoxAllocator,
}

impl<F> RemoteProcedure<F>
where
    F: FunctionPtr,
{
    fn new(ptr: F, remote_allocator: RemoteBoxAllocator) -> Self {
        Self {
            ptr,
            remote_allocator,
        }
    }

    /// Returns the process that this remote procedure is from.
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.remote_allocator.process()
    }

    /// Returns the underlying pointer to the remote procedure.
    pub fn as_ptr(&self) -> F {
        self.ptr
    }

    /// Returns the raw underlying pointer to the remote procedure.
    pub fn as_raw_ptr(&self) -> RawFunctionPtr {
        self.ptr.as_ptr()
    }
}

impl<F> RemoteProcedure<F>
where
    F: FunctionPtr,
    for<'r> F::RefArgs<'r>: Serialize,
    F::Output: DeserializeOwned,
{
    /// Calls the remote procedure with the given arguments.
    pub fn call_with_args(&self, args: F::RefArgs<'_>) -> Result<F::Output, RpcError> {
        let local_arg_buf = bincode::serialize(&args)?;

        // Allocate a buffer in the remote process to hold the argument.
        let remote_arg_buf = self.remote_allocator.alloc_raw(local_arg_buf.len())?;
        remote_arg_buf.write_bytes(local_arg_buf.as_ref())?;
        let parameter_buf = self
            .remote_allocator
            .alloc_uninit::<ArgAndResultBufInfo>()?;

        // build the remote procedure stub
        let code = if self.remote_allocator.process().is_x86()? {
            Self::build_call_procedure_x86(self.ptr, parameter_buf.as_ptr().as_ptr()).unwrap()
        } else {
            Self::build_call_procedure_x64(self.ptr, parameter_buf.as_ptr().as_ptr()).unwrap()
        };
        let code = self.remote_allocator.alloc_and_copy_buf(code.as_slice())?;
        code.memory().flush_instruction_cache()?;

        let stub = RemoteProcedureStub {
            code,
            parameter: parameter_buf,
            result: self.remote_allocator.alloc_uninit::<()>()?,
        };

        // Call the remote procedure stub.
        stub.call(&ArgAndResultBufInfo {
            data: remote_arg_buf.as_ptr().as_ptr() as u64,
            len: remote_arg_buf.len() as u64,
            is_error: false,
        })?;

        let result_buf_info = stub.parameter.read()?;

        // Prepare local result buffer
        let mut local_result_buf = local_arg_buf;
        let result_buf_len = result_buf_info.len as usize;
        if result_buf_len > local_result_buf.len() {
            local_result_buf.reserve(result_buf_len - local_result_buf.len());
        }
        unsafe { local_result_buf.set_len(result_buf_len) };

        // Copy remote buffer into local one.
        if result_buf_info.data == remote_arg_buf.as_ptr().as_ptr() as u64 {
            // The result is in the same buffer as the arguments.
            // We can just read the result from the buffer.
            remote_arg_buf.read_bytes(local_result_buf.as_mut())?;
        } else {
            // The result is in a different buffer.
            let result_memory = unsafe {
                ProcessMemoryBuffer::from_raw_parts(
                    result_buf_info.data as *mut u8,
                    result_buf_info.len as usize,
                    self.process(),
                )
            };
            result_memory.read(0, &mut local_result_buf)?;
        };

        if result_buf_info.is_error {
            Err(RpcError::RemoteProcedure(unsafe {
                String::from_utf8_unchecked(local_result_buf)
            }))
        } else {
            Ok(bincode::deserialize(&local_result_buf)?)
        }
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_procedure_x86<Fn: FunctionPtr>(
        procedure: Fn,
        params_buf: *mut ArgAndResultBufInfo,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!params_buf.is_null());
        assert_eq!(
            procedure.as_ptr() as u32 as usize,
            procedure.as_ptr() as usize
        );
        assert_eq!(params_buf as u32 as usize, params_buf as usize);

        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // load arg ptr (lpParameter) from stack
        asm.push(eax)?; // push arg ptr onto stack
        asm.mov(eax, procedure.as_ptr() as u32)?; // load address of target function
        asm.call(eax)?; // call real_address
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "CallProcedure x86 stub is not location independent"
        );

        Ok(code)
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_procedure_x64<Fn: FunctionPtr>(
        procedure: Fn,
        params_buf: *mut ArgAndResultBufInfo,
    ) -> Result<Vec<u8>, IcedError> {
        assert!(!params_buf.is_null());

        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space
        asm.mov(rcx, rcx)?; // arg ptr
        asm.mov(rax, procedure.as_ptr() as u64)?;
        asm.call(rax)?;
        asm.mov(rax, 0u64)?; // return 0
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.mov(rax, 0u64)?; // return 0
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "CallProcedure x64 stub is not location independent"
        );

        Ok(code)
    }
}

#[derive(Debug)]
pub(crate) struct RemoteProcedureStub<A: ?Sized + Copy, R: Copy> {
    pub code: RemoteAllocation,
    pub parameter: RemoteBox<A>,
    pub result: RemoteBox<R>,
}

impl<A: ?Sized + Copy, R: Copy> RemoteProcedureStub<A, R> {
    pub fn call(&self, args: &A) -> Result<R, RawRpcError> {
        self.parameter.write(args)?;
        let exit_code = self.code.process().run_remote_thread(
            unsafe { mem::transmute(self.code.as_raw_ptr()) },
            self.parameter.as_raw_ptr(),
        )?;
        Syringe::remote_exit_code_to_exception(exit_code)?;

        if mem::size_of::<R>() == 0 {
            Ok(unsafe { mem::zeroed() })
        } else {
            Ok(self.result.read()?)
        }
    }
}

macro_rules! impl_call {
    (@recurse () ($($nm:ident : $ty:ident),*)) => {
        impl_call!(@impl_all ($($nm : $ty),*));
    };
    (@recurse ($hd_nm:ident : $hd_ty:ident $(, $tl_nm:ident : $tl_ty:ident)*) ($($nm:ident : $ty:ident),*)) => {
        impl_call!(@impl_all ($($nm : $ty),*));
        impl_call!(@recurse ($($tl_nm : $tl_ty),*) ($($nm : $ty,)* $hd_nm : $hd_ty));
    };

    (@impl_all ($($nm:ident : $ty:ident),*)) => {
        impl <$($ty,)* Output> RemoteProcedure<fn($($ty),*) -> Output> where $($ty: 'static + Serialize,)* Output: 'static + DeserializeOwned,  {
            /// Calls the remote procedure with the given arguments.
            #[allow(clippy::too_many_arguments)]
            pub fn call(&self, $($nm: &$ty),*) -> Result<Output, RpcError> {
                self.call_with_args(($($nm,)*))
            }
        }

        impl <$($ty,)* Output> RemoteProcedure<unsafe fn($($ty),*) -> Output> where $($ty: 'static + Serialize,)* Output: 'static + DeserializeOwned,  {
            /// Calls the remote procedure with the given arguments.
            ///
            /// # Safety
            /// The caller must ensure whatever the requirements of the underlying remote procedure are.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn call(&self, $($nm: &$ty),*) -> Result<Output, RpcError> {
                self.call_with_args(($($nm,)*))
            }
        }
    };

    (@count ()) => {
        0
    };
    (@count ($hd:tt $($tl:tt)*)) => {
        1 + impl_call!(@count ($($tl)*))
    };

    ($($nm:ident : $ty:ident),*) => {
        impl_call!(@recurse ($($nm : $ty),*) ());
    };
}

impl_call! {
    arg0:  A, arg1:  B, arg2:  C, arg3:  D, arg4:  E, arg5:  F,arg6:  G,
    arg7:  H, arg8:  I, arg9:  J, arg10: K, arg11: L
}
