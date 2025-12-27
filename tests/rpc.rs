#![cfg(feature = "rpc-core")]

use dll_syringe::{process::Process, Syringe};

#[allow(unused)]
mod common;

mod core {
    pub use super::*;
    use std::time::Duration;

    process_test! {
        fn get_procedure_address_of_win32_fn(
            process: OwnedProcess,
        ) {
            let syringe = Syringe::for_process(process);

            let module = syringe.process().wait_for_module_by_name("kernel32.dll", Duration::from_secs(1)).unwrap().unwrap();
            let open_process = syringe.get_procedure_address(
                module,
                "OpenProcess",
            ).unwrap();
            assert!(open_process.is_some());
        }
    }

    syringe_test! {
        fn get_procedure_address_of_dll_main(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let dll_main = syringe.get_procedure_address(module, "DllMain").unwrap();
            assert!(dll_main.is_some());
        }
    }

    process_test! {
        fn get_procedure_address_of_invalid(
            process: OwnedProcess,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.process().wait_for_module_by_name("kernel32.dll", Duration::from_secs(1)).unwrap().unwrap();
            let invalid = syringe.get_procedure_address(module, "ProcedureThatDoesNotExist").unwrap();
            assert!(invalid.is_none());
        }
    }
}

#[cfg(feature = "rpc-payload")]
mod payload {
    pub use super::*;
    use dll_syringe::rpc::PayloadRpcError;

    syringe_test! {
        fn call_simple(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_add = unsafe { syringe.get_payload_procedure::<fn(u32, u32) -> u32>(module, "add") }.unwrap().unwrap();
            let add_result = remote_add.call(&42, &10).unwrap();
            assert_eq!(add_result, 52);
        }
    }

    syringe_test! {
        fn call_complex(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sum = unsafe { syringe.get_payload_procedure::<fn(Vec<u64>) -> u64>(module, "sum") }.unwrap().unwrap();
            let sum_result = remote_sum.call(&vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
            assert_eq!(sum_result, 45);
        }
    }

    syringe_test! {
        fn call_panic(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_does_panic = unsafe { syringe.get_payload_procedure::<fn()>(module, "does_panic") }.unwrap().unwrap();
            let result = remote_does_panic.call();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(matches!(err, PayloadRpcError::RemoteProcedure(_)));
            let err_message = match err {
                PayloadRpcError::RemoteProcedure(e) => e,
                _ => panic!("Expected RpcError::RemoteProcedure"),
            };
            assert_eq!(err_message, String::from("Some error message"));
        }
    }
}

#[cfg(feature = "rpc-raw")]
mod raw {
    pub use super::*;
    use dll_syringe::rpc::RawRpcError;

    syringe_test! {
        fn call_simple(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_add = unsafe { syringe.get_raw_procedure::<extern "system" fn(u32, u32) -> u32>(module, "add_raw") }.unwrap().unwrap();
            let add_result = remote_add.call(42, 10).unwrap();
            assert_eq!(add_result, 52);
        }
    }

    syringe_test! {
        fn call_correct_order(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sub = unsafe { syringe.get_raw_procedure::<extern "system" fn(u32, u32) -> u32>(module, "sub_raw") }.unwrap().unwrap();
            let sub_result = remote_sub.call(42, 10).unwrap();
            assert_eq!(sub_result, 32);
        }
    }

    syringe_test! {
        fn call_small_args(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_add = unsafe { syringe.get_raw_procedure::<extern "system" fn(u16, u8) -> u16>(module, "add_smol_raw") }.unwrap().unwrap();
            let add_result = remote_add.call(42, 10).unwrap();
            assert_eq!(add_result, 52);
        }
    }

    syringe_test! {
        fn call_many_args(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sum = unsafe { syringe.get_raw_procedure::<extern "system" fn(u32, u32, u32, u32, u32) -> u32>(module, "sum_5_raw") }.unwrap().unwrap();
            let sum_result = remote_sum.call(1, 2, 3, 4, 5).unwrap();
            assert_eq!(sum_result, 15);
        }
    }

    syringe_test! {
        fn call_many_args2(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sum = unsafe { syringe.get_raw_procedure::<extern "system" fn(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32) -> u32>(module, "sum_10_raw") }.unwrap().unwrap();
            let sum_result = remote_sum.call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).unwrap();
            assert_eq!(sum_result, 55);
        }
    }

    syringe_test! {
        fn call_float_args_and_result(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sub = unsafe { syringe.get_raw_procedure::<extern "system" fn(f32, f32) -> f32>(module, "sub_float_raw") }.unwrap().unwrap();
            let sub_result = remote_sub.call(1.2, 0.2).unwrap();
            assert_eq!(sub_result, 1.0);

    syringe_test! {
        fn call_integral_and_float_mixed(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_add = unsafe { syringe.get_raw_procedure::<extern "system" fn(f32, u32) -> f32>(module, "add_raw_mixed") }.unwrap().unwrap();
            let add_result = remote_add.call(1.1, 1).unwrap();
            assert_eq!(add_result, 2.1);
        }
    }
        }
    }

    syringe_test! {
        fn call_simple_c_call(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_add = unsafe { syringe.get_raw_procedure::<extern "C" fn(u32, u32) -> u32>(module, "add_raw_c") }.unwrap().unwrap();
            let add_result = remote_add.call(42, 10).unwrap();
            assert_eq!(add_result, 52);
        }
    }

    syringe_test! {
        fn call_many_args2_c_call(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();

            let remote_sum = unsafe { syringe.get_raw_procedure::<extern "C" fn(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32) -> u32>(module, "sum_10_raw_c") }.unwrap().unwrap();
            let sum_result = remote_sum.call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).unwrap();
            assert_eq!(sum_result, 55);
        }
    }

    syringe_test! {
        fn call_after_eject_fails_with_inaccessible_module(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();
            let remote_add = unsafe { syringe.get_raw_procedure::<extern "C" fn(u32, u32) -> u32>(module, "add_raw_c") }.unwrap().unwrap();
            syringe.eject(module).unwrap();
            let add_err = remote_add.call(42, 10).unwrap_err();
            assert!(matches!(add_err, RawRpcError::ModuleInaccessible));
        }
    }

    syringe_test! {
        fn call_after_kill_fails_with_inaccessible_process(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();
            let remote_add = unsafe { syringe.get_raw_procedure::<extern "C" fn(u32, u32) -> u32>(module, "add_raw_c") }.unwrap().unwrap();
            syringe.process().kill().unwrap();
            let add_err = remote_add.call(42, 10).unwrap_err();
            assert!(matches!(add_err, RawRpcError::ProcessInaccessible), "{add_err:?}");
        }
    }

    syringe_test! {
        fn call_crash_fails_with_access_violation(
            process: OwnedProcess,
            payload_path: &Path,
        ) {
            let syringe = Syringe::for_process(process);
            let module = syringe.inject(payload_path).unwrap();
            let remote_add = unsafe { syringe.get_raw_procedure::<extern "C" fn()>(module, "crash") }.unwrap().unwrap();
            let add_err = remote_add.call().unwrap_err();
            assert!(matches!(add_err, RawRpcError::RemoteException(dll_syringe::error::ExceptionCode::AccessViolation)), "{add_err:?}");
        }
    }
}
