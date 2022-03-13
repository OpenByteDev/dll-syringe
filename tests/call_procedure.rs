#![cfg(feature = "rpc")]

use dll_syringe::{error::RpcError, process::Process, Syringe};
use std::time::Duration;

#[allow(unused)]
mod common;

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

syringe_test! {
    fn call_procedure_with_payload_utils_simple(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();

        let remote_add = syringe.get_procedure::<fn(u32, u32) -> u32>(module, "add3").unwrap().unwrap();
        let add_result = remote_add.call(&42, &10).unwrap();
        assert_eq!(add_result, 52);
    }
}

syringe_test! {
    fn call_procedure_with_payload_utils_complex(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();

        let remote_sum = syringe.get_procedure::<fn(Vec<u64>) -> u64>(module, "sum").unwrap().unwrap();
        let sum_result = remote_sum.call(&vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(sum_result, 45);
    }
}

syringe_test! {
    fn call_procedure_with_payload_utils_panic(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();

        let remote_does_panic = syringe.get_procedure::<fn()>(module, "does_panic").unwrap().unwrap();
        let result = remote_does_panic.call();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RpcError::RemoteProcedure(_)));
        let err_message = match err {
            RpcError::RemoteProcedure(e) => e.to_string(),
            _ => panic!("Expected RpcError::RemoteProcedure"),
        };
        assert_eq!(err_message, String::from("Some error message"));
    }
}
