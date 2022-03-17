use serde::{de::DeserializeOwned, Serialize};

use std::{any::type_name, marker::PhantomData, fmt};

use crate::{
    error::SyringeError,
    function::{FunctionPtr, RawFunctionPtr},
    process::{
        memory::{ProcessMemoryBuffer, RemoteBoxAllocator},
        BorrowedProcess, BorrowedProcessModule,
    },
    rpc::{RemoteRawProcedure, Truncate, error::PayloadRpcError},
    ArgAndResultBufInfo, Syringe,
};

#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-payload")))]
impl Syringe {
    #[allow(rustdoc::broken_intra_doc_links)]
    /// Loads an exported function from the given module from the target process.
    ///
    /// # Note
    /// The function does not have to be from an injected module.
    /// If the module is not loaded in the target process `Ok(None)` is returned.
    ///
    /// # Safety
    /// The target function must abide by the given signature and has to be declared using the [`payload_procedure!`](crate::payload_procedure) macro.
    pub unsafe fn get_payload_procedure<F: PayloadRpcFunctionPtr>(
        &self,
        module: BorrowedProcessModule<'_>,
        name: &str,
    ) -> Result<Option<RemotePayloadProcedure<F>>, SyringeError> {
        match self.get_procedure_address(module, name) {
            Ok(Some(procedure)) => Ok(Some(RemotePayloadProcedure::new(
                unsafe { RealPayloadRpcFunctionPtr::from_ptr(procedure) },
                self.remote_allocator.clone(),
            ))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A function pointer that can be used with [`RemotePayloadProcedure`].
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-payload")))]
pub trait PayloadRpcFunctionPtr: FunctionPtr {}

type RealPayloadRpcFunctionPtr = extern "system" fn(Truncate<*mut ArgAndResultBufInfo>);

/// A struct representing a procedure from a module of a remote process.
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-payload")))]
pub struct RemotePayloadProcedure<F> {
    ptr: RealPayloadRpcFunctionPtr,
    remote_allocator: RemoteBoxAllocator,
    phantom: PhantomData<fn() -> F>,
}

impl <F> fmt::Debug for RemotePayloadProcedure<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(type_name::<RemotePayloadProcedure<F>>())
            .field("ptr", &self.ptr.as_ptr())
            .field("remote_allocator", &self.remote_allocator)
            .field("phantom", &self.phantom)
            .finish()
    }
}

impl<F> RemotePayloadProcedure<F>
where
    F: FunctionPtr,
{
    pub(crate) fn new(ptr: RealPayloadRpcFunctionPtr, remote_allocator: RemoteBoxAllocator) -> Self {
        Self {
            ptr,
            remote_allocator,
            phantom: PhantomData
        }
    }

    /// Returns the process that this remote procedure is from.
    pub fn process(&self) -> BorrowedProcess<'_> {
        self.remote_allocator.process()
    }

    /// Returns the raw underlying pointer to the remote procedure.
    pub fn as_raw_ptr(&self) -> RawFunctionPtr {
        self.ptr.as_ptr()
    }
}

impl<F> RemotePayloadProcedure<F>
where
    F: PayloadRpcFunctionPtr,
    for<'r> F::RefArgs<'r>: Serialize,
    F::Output: DeserializeOwned,
{
    fn call_with_args(&self, args: F::RefArgs<'_>) -> Result<F::Output, PayloadRpcError> {
        let local_arg_buf = bincode::serialize(&args)?;

        let stub = RemoteRawProcedure::new(
            self.ptr,
            self.remote_allocator.clone(),
        );

        // Allocate a buffer in the remote process to hold the argument.
        let remote_arg_buf = self.remote_allocator.alloc_raw(local_arg_buf.len())?;
        remote_arg_buf.write_bytes(local_arg_buf.as_ref())?;

        let parameter_buf = self
            .remote_allocator
            .alloc_and_copy(&ArgAndResultBufInfo {
                data: remote_arg_buf.as_ptr().as_ptr() as u64,
                len: remote_arg_buf.len() as u64,
                is_error: false,
            })?;

        // Call the remote procedure stub.
        stub.call(Truncate(parameter_buf.as_ptr().as_ptr()))?;

        let result_buf_info = parameter_buf.read()?;

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
            Err(PayloadRpcError::RemoteProcedure(unsafe {
                String::from_utf8_unchecked(local_result_buf)
            }))
        } else {
            Ok(bincode::deserialize(&local_result_buf)?)
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
        impl <$($ty,)* Output> PayloadRpcFunctionPtr for fn($($ty),*) -> Output where $($ty : 'static + Serialize,)* Output: 'static + DeserializeOwned { }
        impl <$($ty,)* Output> PayloadRpcFunctionPtr for unsafe fn($($ty),*) -> Output where $($ty : 'static + Serialize,)* Output: 'static + DeserializeOwned { }

        impl <$($ty,)* Output> RemotePayloadProcedure<fn($($ty),*) -> Output> where $($ty: 'static + Serialize,)* Output: 'static + DeserializeOwned,  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are serialized using [bincode](https://crates.io/crates/bincode).
            #[allow(clippy::too_many_arguments)]
            pub fn call(&self, $($nm: &$ty),*) -> Result<Output, PayloadRpcError> {
                self.call_with_args(($($nm,)*))
            }
        }

        impl <$($ty,)* Output> RemotePayloadProcedure<unsafe fn($($ty),*) -> Output> where $($ty: 'static + Serialize,)* Output: 'static + DeserializeOwned,  {
            /// Calls the remote procedure with the given arguments.
            /// The arguments and the return value are serialized using [bincode](https://crates.io/crates/bincode).
            ///
            /// # Safety
            /// The caller must ensure whatever the requirements of the underlying remote procedure are.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn call(&self, $($nm: &$ty),*) -> Result<Output, PayloadRpcError> {
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
