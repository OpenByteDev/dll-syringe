use iced_x86::{code_asm::*, IcedError};

use std::{
    ffi::CString,
    mem,
    ptr::{self, NonNull},
};

use crate::{
    error::LoadProcedureError,
    function::{FunctionPtr, RawFunctionPtr},
    process::{
        memory::{RemoteAllocation, RemoteBox},
        BorrowedProcessModule, Process,
    },
    rpc::error::RawRpcError,
    GetProcAddressFn, Syringe,
};

#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-core")))]
impl Syringe {
    /// Load the address of the given function from the given module in the remote process.
    pub fn get_procedure_address(
        &self,
        module: BorrowedProcessModule<'_>,
        name: impl AsRef<str>,
    ) -> Result<Option<RawFunctionPtr>, LoadProcedureError> {
        assert!(
            module.process() == &self.process(),
            "trying to get a procedure from a module from a different process"
        );

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
    ) -> Result<&RemoteProcedureStub<GetProcAddressParams, RawFunctionPtr>, LoadProcedureError>
    {
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

#[derive(Debug)]
pub(crate) struct RemoteProcedureStub<A: ?Sized + Copy, R: Copy> {
    pub code: RemoteAllocation,
    pub parameter: RemoteBox<A>,
    pub result: RemoteBox<R>,
}

impl<A: ?Sized + Copy, R: Copy> RemoteProcedureStub<A, R> {
    #[allow(dead_code)]
    pub(crate) fn call(&self, args: &A) -> Result<R, RawRpcError> {
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
