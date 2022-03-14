use iced_x86::{code_asm::*, IcedError};
use serde::{de::DeserializeOwned, Serialize};

use std::{
    ffi::CString,
    mem,
    ptr::{self, NonNull},
    any::TypeId, io
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
    fn call_with_args(&self, args: F::RefArgs<'_>) -> Result<F::Output, RpcError> {
        let local_arg_buf = bincode::serialize(&args)?;

        // Allocate a buffer in the remote process to hold the argument.
        let remote_arg_buf = self.remote_allocator.alloc_raw(local_arg_buf.len())?;
        remote_arg_buf.write_bytes(local_arg_buf.as_ref())?;
        let parameter_buf = self
            .remote_allocator
            .alloc_uninit::<ArgAndResultBufInfo>()?;

        // build the remote procedure stub
        let code = if self.remote_allocator.process().is_x86()? {
            Self::build_call_stub_x86(self.ptr).unwrap()
        } else {
            Self::build_call_stub_x64(self.ptr).unwrap()
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
    fn build_call_stub_x86(procedure: F) -> Result<Vec<u8>, IcedError> {
        assert_eq!(
            procedure.as_ptr() as u32 as usize,
            procedure.as_ptr() as usize
        );

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
            "call x86 stub is not location independent"
        );

        Ok(code)
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_stub_x64(procedure: F) -> Result<Vec<u8>, IcedError> {
        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 40)?; // Re-align stack to 16 byte boundary +32 shadow space
        asm.mov(rcx, rcx)?; // arg ptr
        asm.mov(rax, procedure.as_ptr() as u64)?;
        asm.call(rax)?;
        asm.mov(rax, 0u64)?; // return 0
        asm.add(rsp, 40)?; // Re-align stack to 16 byte boundary + shadow space.
        asm.ret()?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "call x64 stub is not location independent"
        );

        Ok(code)
    }
}

impl<F> RemoteProcedure<F>
where
    F: FunctionPtr,
{
    fn call_raw_with_args(&self, args: &[usize], float_mask: u32) -> Result<F::Output, RawRpcError>
    where
        F::Output: Copy,
    {
        let parameter_buf = self.remote_allocator.alloc_and_copy_buf(args)?;
        let parameter_buf = unsafe { RemoteBox::<[usize]>::new(parameter_buf) };
        let result_buf = self.remote_allocator.alloc_uninit::<usize>()?;

        let code = if self.process().is_x86()? {
            Self::build_call_raw_stub_x86(self.ptr, result_buf.as_ptr().as_ptr(), float_mask).unwrap()
        } else {
            Self::build_call_raw_stub_x64(self.ptr, result_buf.as_ptr().as_ptr(), float_mask).unwrap()
        };
        let code = self.remote_allocator.alloc_and_copy_buf(code.as_slice())?;
        code.memory().flush_instruction_cache()?;

        let exit_code = code.process().run_remote_thread(
            unsafe { mem::transmute(code.as_raw_ptr()) },
            parameter_buf.as_raw_ptr(),
        )?;
        Syringe::remote_exit_code_to_exception(exit_code)?;

        if mem::size_of::<F::Output>() == 0 {
            Ok(unsafe { mem::zeroed() })
        } else {
            let result = unsafe { result_buf.memory().read_struct::<F::Output>(0)? };
            Ok(result)
        }
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_raw_stub_x86(procedure: F, result_buf: *mut usize, _float_mask: u32) -> Result<Vec<u8>, IcedError> {
        assert!(!result_buf.is_null());
        assert_eq!(
            procedure.as_ptr() as u32 as usize,
            procedure.as_ptr() as usize
        );
        assert_eq!(result_buf as u32 as usize, result_buf as usize);

        let mut asm = CodeAssembler::new(32)?;

        asm.mov(eax, esp + 4)?; // load arg ptr (lpParameter) from stack
        for i in (0..F::ARITY).rev() {
            asm.push(dword_ptr(eax + (i * mem::size_of::<usize>())))?;
        }
        asm.mov(eax, procedure.as_ptr() as u32)?; // load address of target function
        asm.call(eax)?; // call real_address
        asm.mov(dword_ptr(result_buf as u32), eax)?; // write result to result buf
        asm.mov(eax, 0)?; // return 0
        asm.ret_1(4)?; // Restore stack ptr. (Callee cleanup)

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "call raw x86 stub is not location independent"
        );

        Ok(code)
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_raw_stub_x64(procedure: F, result_buf: *mut usize, float_mask: u32) -> Result<Vec<u8>, IcedError> {
        let mut asm = CodeAssembler::new(64)?;

        asm.mov(rax, rcx)?; // arg base ptr
        if F::ARITY > 0 {
            asm.mov(rcx, qword_ptr(rax + (0 * mem::size_of::<usize>())))?;
            if float_mask & (1 << 0) != 0 {
                asm.movq(xmm0, rcx)?;
            }
        }
        if F::ARITY > 1 {
            asm.mov(rdx, qword_ptr(rax + (1 * mem::size_of::<usize>())))?;
            if float_mask & (1 << 1) != 0 {
                asm.movq(xmm1, rdx)?;
            }
        }
        if F::ARITY > 2 {
            asm.mov(r8, qword_ptr(rax + (2 * mem::size_of::<usize>())))?;
            if float_mask & (1 << 2) != 0 {
               asm.movq(xmm2, r8)?;
            }
        }
        if F::ARITY > 3 {
            asm.mov(r9, qword_ptr(rax + (3 * mem::size_of::<usize>())))?;
            if float_mask & (1 << 3) != 0 {
                asm.movq(xmm3, r9)?;
            }
        }
        for i in (4..F::ARITY).rev() {
            asm.push(qword_ptr(rax + (i * mem::size_of::<usize>())))?;
        }
        
        asm.mov(rax, procedure.as_ptr() as u64)?;

        asm.sub(rsp, 32)?; // push shadow space
        asm.call(rax)?;
        asm.add(rsp, 32)?; // pop shadow space
        
        // write result to result buf
        if float_mask & 0x8000_0000u32 != 0 {
            asm.movq(rax, xmm0)?;
        } 
        asm.mov(qword_ptr(result_buf as u64), rax)?; 

        asm.mov(rax, 0u64)?; // return 0
        
        if F::ARITY > 4 {
            asm.add(rsp, ((F::ARITY - 4) * mem::size_of::<usize>()) as i32)?;
        }

        asm.ret()?; // Restore stack ptr.

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "call x64 stub is not location independent"
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

/*
// from https://stackoverflow.com/a/60138532/6304917
/// Are `T` and `U` are the same type?
const fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    // Helper trait. `VALUE` is false, except for the specialization of the
    // case where `T == U`.
    trait TypeEq<U: ?Sized> {
        const VALUE: bool;
    }

    // Default implementation.
    impl<T: ?Sized, U: ?Sized> TypeEq<U> for T {
        default const VALUE: bool = false;
    }

    // Specialization for `T == U`.
    impl<T: ?Sized> TypeEq<T> for T {
        const VALUE: bool = true;
    }

    <T as TypeEq<U>>::VALUE
}
*/
fn type_eq<T: ?Sized + 'static, U: ?Sized + 'static>() -> bool {
    TypeId::of::<T>() == TypeId::of::<U>()
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
            /// The arguments and the return value are serialized using [bincode](https://crates.io/crates/bincode).
            #[allow(clippy::too_many_arguments)]
            pub fn call(&self, $($nm: &$ty),*) -> Result<Output, RpcError> {
                self.call_with_args(($($nm,)*))
            }
        }

        impl <$($ty,)* Output> RemoteProcedure<unsafe fn($($ty),*) -> Output> where $($ty: 'static + Serialize,)* Output: 'static + DeserializeOwned,  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are serialized using [bincode](https://crates.io/crates/bincode).
            ///
            /// # Safety
            /// The caller must ensure whatever the requirements of the underlying remote procedure are.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn call(&self, $($nm: &$ty),*) -> Result<Output, RpcError> {
                self.call_with_args(($($nm,)*))
            }
        }

        impl <$($ty,)* Output> RemoteProcedure<fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            fn build_args_buf_and_float_mask(process: BorrowedProcess<'_>, $($nm: $ty),*) -> io::Result<([usize; impl_call!(@count ($($ty)*))], u32)> {
                let target_pointer_size = if process.is_x86()? {
                    4
                } else {
                    8
                };

                // store arguments as a usize buffer (avoids handling different sized arguments explicitly)
                let args_buf = [$({
                    assert!(mem::size_of::<$ty>() <= target_pointer_size, "argument of type {} is too large to fit in an argument", stringify!($ty));

                    let mut buf = [0u8; mem::size_of::<usize>()];
                    for i in 0..mem::size_of::<$ty>() {
                        buf[i] = unsafe { *(&$nm as *const $ty as *const u8).add(i) };
                    }
                    unsafe { mem::transmute::<[u8; mem::size_of::<usize>()], usize>(buf) }
                },)*];

                // calculate a mask denoting which arguments are floats
                let mut float_mask = 0u32;
                $(float_mask = (float_mask << 1) | if type_eq::<$ty, f32>() || type_eq::<$ty, f64>() { 1 } else { 0 };)*
                float_mask = float_mask | if type_eq::<Output, f32>() || type_eq::<Output, f64>() { 0x8000_0000u32 } else { 0 };

                // use var to avoid dead_code warning
                let _ = target_pointer_size;

                Ok((args_buf, float_mask))
            }
        }

        impl <$($ty,)* Output> RemoteProcedure<extern "system" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            #[allow(clippy::too_many_arguments)]
            pub fn call_raw(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let target_pointer_size = if self.process().is_x86()? {
                    4
                } else {
                    8
                };

                // store arguments as a usize buffer (avoids handling different sized arguments explicitly)
                let args_buf = [$({
                    assert!(mem::size_of::<$ty>() <= target_pointer_size, "argument of type {} is too large to fit in an argument", stringify!($ty));

                    let mut buf = [0u8; mem::size_of::<usize>()];
                    for i in 0..mem::size_of::<$ty>() {
                        buf[i] = unsafe { *(&$nm as *const $ty as *const u8).add(i) };
                    }
                    unsafe { mem::transmute::<[u8; mem::size_of::<usize>()], usize>(buf) }
                },)*];

                // calculate a mask denoting which arguments are floats
                let mut float_mask = 0u32;
                $(float_mask = (float_mask << 1) | if type_eq::<$ty, f32>() || type_eq::<$ty, f64>() { 1 } else { 0 };)*
                float_mask = float_mask | if type_eq::<Output, f32>() || type_eq::<Output, f64>() { 0x8000_0000u32 } else { 0 };

                // use var to avoid dead_code warning
                let _ = target_pointer_size;

                self.call_raw_with_args(&args_buf, float_mask)
            }
        }

        impl <$($ty,)* Output> RemoteProcedure<extern "C" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            #[allow(clippy::too_many_arguments)]
            pub fn call_raw(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let target_pointer_size = if self.process().is_x86()? {
                    4
                } else {
                    8
                };

                // store arguments as a usize buffer (avoids handling different sized arguments explicitly)
                let args_buf = [$({
                    assert!(mem::size_of::<$ty>() <= target_pointer_size, "argument of type {} is too large to fit in an argument", stringify!($ty));

                    let mut buf = [0u8; mem::size_of::<usize>()];
                    for i in 0..mem::size_of::<$ty>() {
                        buf[i] = unsafe { *(&$nm as *const $ty as *const u8).add(i) };
                    }
                    unsafe { mem::transmute::<[u8; mem::size_of::<usize>()], usize>(buf) }
                },)*];

                // calculate a mask denoting which arguments are floats
                let mut float_mask = 0u32;
                $(float_mask = (float_mask << 1) | if type_eq::<$ty, f32>() || type_eq::<$ty, f64>() { 1 } else { 0 };)*
                float_mask = float_mask | if type_eq::<Output, f32>() || type_eq::<Output, f64>() { 0x8000_0000u32 } else { 0 };

                // use var to avoid dead_code warning
                let _ = target_pointer_size;

                self.call_raw_with_args(&args_buf, float_mask)
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
