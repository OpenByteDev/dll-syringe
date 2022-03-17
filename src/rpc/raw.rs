use iced_x86::{code_asm::*, IcedError};

use std::{
    any::{self, type_name, TypeId},
    io,
    lazy::OnceCell,
    mem,
};

use crate::{
    error::SyringeError,
    function::{Abi, FunctionPtr},
    process::{
        memory::{RemoteAllocation, RemoteBox, RemoteBoxAllocator},
        BorrowedProcess, BorrowedProcessModule, Process,
    },
    rpc::{error::RawRpcError, RemoteProcedure},
    Syringe,
};

#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-raw")))]
impl Syringe {
    /// Loads an exported function from the given module from the target process.
    /// Only exported functions with a calling convention of `C` or `system` are supported.
    ///
    /// Loads an exported function from the given module from the target process.
    ///
    /// # Note
    /// The function does not have to be from an injected module.
    /// If the module is not loaded in the target process `Ok(None)` is returned.
    ///
    /// # Safety
    /// The target function must abide by the given signature.
    pub unsafe fn get_raw_procedure<F: RawRpcFunctionPtr>(
        &self,
        module: BorrowedProcessModule<'_>,
        name: &str,
    ) -> Result<Option<RemoteRawProcedure<F>>, SyringeError> {
        match self.get_procedure_address(module, name) {
            Ok(Some(procedure)) => Ok(Some(RemoteRawProcedure::new(
                unsafe { F::from_ptr(procedure) },
                self.remote_allocator.clone(),
            ))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A function pointer that can be used with [`RemoteRawProcedure`].
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-raw")))]
pub trait RawRpcFunctionPtr: FunctionPtr {}

/// A struct representing a procedure from a module of a remote process.
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-raw")))]
#[derive(Debug)]
pub struct RemoteRawProcedure<F> {
    ptr: F,
    remote_allocator: RemoteBoxAllocator,
    stub: OnceCell<RemoteRawProcedureStub>,
}

#[derive(Debug)]
pub(crate) struct RemoteRawProcedureStub {
    pub code: RemoteAllocation,
    pub parameter: RemoteAllocation,
    pub result: RemoteBox<usize>,
}

impl<F> RemoteRawProcedure<F>
where
    F: FunctionPtr,
{
    fn new(ptr: F, remote_allocator: RemoteBoxAllocator) -> Self {
        Self {
            ptr,
            remote_allocator,
            stub: OnceCell::new(),
        }
    }
}

impl<F> RemoteProcedure<F> for RemoteRawProcedure<F>
where
    F: FunctionPtr,
{
    /// Returns the process that this remote procedure is from.
    fn process(&self) -> BorrowedProcess<'_> {
        self.remote_allocator.process()
    }

    /// Returns the underlying pointer to the remote procedure.
    fn as_ptr(&self) -> F {
        self.ptr
    }
}

impl<F> RemoteRawProcedure<F>
where
    F: RawRpcFunctionPtr,
{
    fn call_with_args(&self, args: &[usize]) -> Result<F::Output, RawRpcError> {
        let stub = self.build_call_stub()?;

        stub.parameter.memory().write_struct(0, args)?;

        let exit_code = stub.code.process().run_remote_thread(
            unsafe { mem::transmute(stub.code.as_raw_ptr()) },
            stub.parameter.as_raw_ptr(),
        )?;
        Syringe::remote_exit_code_to_exception(exit_code)?;

        if mem::size_of::<F::Output>() == 0 {
            Ok(unsafe { mem::zeroed() })
        } else {
            let result = unsafe { stub.result.memory().read_struct::<F::Output>(0)? };
            Ok(result)
        }
    }

    fn build_call_stub(&self) -> Result<&RemoteRawProcedureStub, io::Error> {
        self.stub.get_or_try_init(|| {
            let parameter = self.remote_allocator.alloc_buf::<usize>(F::ARITY)?;
            let result = self.remote_allocator.alloc_uninit::<usize>()?;

            let float_mask = <F::NonExtern>::build_float_mask();
            let code = if self.process().is_x86()? {
                Self::build_call_stub_x86(self.ptr, result.as_ptr().as_ptr(), float_mask).unwrap()
            } else {
                Self::build_call_stub_x64(self.ptr, result.as_ptr().as_ptr(), float_mask).unwrap()
            };
            let code = self.remote_allocator.alloc_and_copy_buf(code.as_slice())?;
            code.memory().flush_instruction_cache()?;

            Ok(RemoteRawProcedureStub {
                code,
                parameter,
                result,
            })
        })
    }

    #[allow(clippy::fn_to_numeric_cast, clippy::fn_to_numeric_cast_with_truncation)]
    fn build_call_stub_x86(
        procedure: F,
        result_buf: *mut usize,
        _float_mask: u32,
    ) -> Result<Vec<u8>, IcedError> {
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

        match F::ABI {
            Abi::C => {
                asm.add(esp, (mem::size_of::<u32>() * F::ARITY) as u32)?;
            }
            Abi::System => {}
            _ => unreachable!(),
        }

        // Restore stack ptr. (Callee cleanup)
        asm.ret_1(4)?;

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "{} call x86 stub is not location independent",
            type_name::<RemoteRawProcedure<F>>()
        );

        Ok(code)
    }

    #[allow(
        clippy::fn_to_numeric_cast,
        clippy::fn_to_numeric_cast_with_truncation,
        clippy::identity_op,
        clippy::erasing_op
    )]
    fn build_call_stub_x64(
        procedure: F,
        result_buf: *mut usize,
        float_mask: u32,
    ) -> Result<Vec<u8>, IcedError> {
        let mut asm = CodeAssembler::new(64)?;

        asm.sub(rsp, 8)?; // align stack to 16 bytes
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

        asm.add(rsp, 8)?; // remove stack alignment
        asm.ret()?; // Restore stack ptr.

        let code = asm.assemble(0x1234_5678)?;
        debug_assert_eq!(
            code,
            asm.assemble(0x1111_2222)?,
            "{} call x64 stub is not location independent",
            type_name::<RemoteRawProcedure<F>>()
        );

        Ok(code)
    }
}

fn type_eq<T: ?Sized + 'static, U: ?Sized + 'static>() -> bool {
    TypeId::of::<T>() == TypeId::of::<U>()
}

/// Helper trait for building a mask of which arguments and results are passed in floating point registers.
trait BuildFloatMask {
    fn build_float_mask() -> u32;
}

#[derive(shrinkwraprs::Shrinkwrap, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Truncate<T>(pub T);

impl<F: FunctionPtr> BuildFloatMask for F {
    default fn build_float_mask() -> u32 {
        // This default implementation will never be called as there exists a specialization for every valid function pointer (defined in the macro below).
        unreachable!()
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
        impl <$($ty,)* Output> RawRpcFunctionPtr for extern "system" fn($($ty),*) -> Output where $($ty : 'static + Copy,)* Output: 'static + Copy { }
        impl <$($ty,)* Output> RawRpcFunctionPtr for unsafe extern "system" fn($($ty),*) -> Output where $($ty : 'static + Copy,)* Output: 'static + Copy { }
        impl <$($ty,)* Output> RawRpcFunctionPtr for extern "C" fn($($ty),*) -> Output where $($ty : 'static + Copy,)* Output: 'static + Copy { }
        impl <$($ty,)* Output> RawRpcFunctionPtr for unsafe extern "C" fn($($ty),*) -> Output where $($ty : 'static + Copy,)* Output: 'static + Copy { }

        impl <$($ty,)* Output> RemoteRawProcedure<fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            #[allow(clippy::too_many_arguments)]
            fn build_args_buf(process: BorrowedProcess<'_>, $($nm: $ty),*) -> io::Result<[usize; impl_call!(@count ($($ty)*))]> {
                let target_pointer_size = if process.is_x86()? {
                    mem::size_of::<u32>()
                } else {
                    mem::size_of::<u64>()
                };

                let truncate_prefix = any::type_name::<Truncate<()>>();
                let truncate_prefix = &truncate_prefix[..(truncate_prefix.len() - "()>".len())];

                // store arguments as a usize buffer (avoids handling different sized arguments explicitly)
                let args_buf = [$({
                    let is_truncate = any::type_name::<$ty>().starts_with(truncate_prefix);

                    assert!(
                        is_truncate || mem::size_of::<$ty>() <= target_pointer_size,
                        "Argument of type {} ({} bit) is too large to fit an a word in the target process ({} bit)",
                        any::type_name::<$ty>(),
                        mem::size_of::<$ty>() * 8,
                        target_pointer_size * 8,
                    );

                    let mut buf = [0u8; mem::size_of::<usize>()];
                    let arg_bytes = unsafe { slice::from_raw_parts(&$nm as *const $ty as *const u8, mem::size_of::<$ty>()) };
                    let truncated_arg_len = cmp::min(mem::size_of::<$ty>(), target_pointer_size);
                    if cfg!(target_endian = "little") {
                        buf[..truncated_arg_len].copy_from_slice(&arg_bytes[..truncated_arg_len]);
                    } else if cfg!(target_endian = "big") {
                        buf[(mem::size_of::<usize>() - truncated_arg_len)..].copy_from_slice(&arg_bytes[(arg_bytes.len() - truncated_arg_len)..]);
                    } else {
                        unreachable!();
                    }
                    unsafe { mem::transmute::<[u8; mem::size_of::<usize>()], usize>(buf) }
                },)*];

                // use vars to avoid dead_code warning
                let _ = target_pointer_size;
                let _ = truncate_prefix;

                Ok(args_buf)
            }
        }

        impl <$($ty,)* Output> BuildFloatMask for fn($($ty),*) -> Output where $($ty : 'static,)* Output: 'static {
            fn build_float_mask() -> u32 {
                // calculate a mask denoting which arguments are floats
                let mut float_mask = 0u32;
                $(float_mask = (float_mask << 1) | if type_eq::<$ty, f32>() || type_eq::<$ty, f64>() { 1 } else { 0 };)*
                float_mask |= if type_eq::<Output, f32>() || type_eq::<Output, f64>() { 0x8000_0000u32 } else { 0 };

                float_mask
            }
        }

        impl <$($ty,)* Output> RemoteRawProcedure<extern "system" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            #[allow(clippy::too_many_arguments)]
            pub fn call(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let args_buf = RemoteRawProcedure::<fn($($ty),*) -> Output>::build_args_buf(self.process(), $($nm),*)?;
                self.call_with_args(&args_buf)
            }
        }
        impl <$($ty,)* Output> RemoteRawProcedure<extern "C" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            #[allow(clippy::too_many_arguments)]
            pub fn call(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let args_buf = RemoteRawProcedure::<fn($($ty),*) -> Output>::build_args_buf(self.process(), $($nm),*)?;
                self.call_with_args(&args_buf)
            }
        }
        impl <$($ty,)* Output> RemoteRawProcedure<unsafe extern "system" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            ///
            /// # Safety
            /// The caller must ensure whatever the requirements of the underlying remote procedure are.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn call(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let args_buf = RemoteRawProcedure::<fn($($ty),*) -> Output>::build_args_buf(self.process(), $($nm),*)?;
                self.call_with_args(&args_buf)
            }
        }
        impl <$($ty,)* Output> RemoteRawProcedure<unsafe extern "C" fn($($ty),*) -> Output> where $($ty : 'static + Copy,)* Output: 'static + Copy  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are copied bytewise.
            ///
            /// # Safety
            /// The caller must ensure whatever the requirements of the underlying remote procedure are.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn call(&self, $($nm: $ty),*) -> Result<Output, RawRpcError> {
                let args_buf = RemoteRawProcedure::<fn($($ty),*) -> Output>::build_args_buf(self.process(), $($nm),*)?;
                self.call_with_args(&args_buf)
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
