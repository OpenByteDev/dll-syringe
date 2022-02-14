#![cfg(feature = "remote_procedure")]

use dll_syringe::Syringe;

#[allow(unused)]
mod common;

process_test! {
    fn get_procedure_address_of_win32_fn(
        process: Process,
    ) {
        let mut syringe = Syringe::for_process(&process);

        let module = process.wait_for_module_by_name("kernel32.dll", std::time::Duration::from_secs(1)).unwrap().unwrap();
        let open_process = syringe.get_procedure_address(
            module,
            "OpenProcess",
        ).unwrap();
        assert!(open_process.is_some());
    }
}

syringe_test! {
    fn get_procedure_address_of_dll_main(
        process: Process,
        payload_path: &Path,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = syringe.inject(payload_path).unwrap();

        let dll_main = syringe.get_procedure_address(module, "DllMain").unwrap();
        assert!(dll_main.is_some());
    }
}

process_test! {
    fn get_procedure_address_of_invaid(
        process: Process,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = process.wait_for_module_by_name("kernel32.dll", std::time::Duration::from_secs(1)).unwrap().unwrap();
        let invalid = syringe.get_procedure_address(module, "ProcedureThatDoesNotExist").unwrap();
        assert!(invalid.is_none());
    }
}

syringe_test! {
    fn call_procedure_simple(
        process: Process,
        payload_path: &Path,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = syringe.inject(payload_path).unwrap();

        // Simple echo test
        let remote_echo = syringe.get_procedure(module, "echo").unwrap();
        assert!(remote_echo.is_some());
        let mut remote_echo = remote_echo.unwrap();
        let echo_result: u32 = remote_echo.call(&0x1234_5678u32).unwrap();
        assert_eq!(echo_result, 0x1234_5678u32);

        // "Complex" addition test
        let mut remote_add = syringe.get_procedure(module, "add").unwrap().unwrap();
        let add_result: f64 = remote_add.call(&(4.2f64, 0.1f64)).unwrap();
        assert_eq!(add_result as f64, 4.2f64 + 0.1f64);
    }
}

syringe_test! {
    fn call_procedure_with_payload_utils(
        process: Process,
        payload_path: &Path,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = syringe.inject(payload_path).unwrap();

        let mut remote_add2 = syringe.get_procedure(module, "add2").unwrap().unwrap();
        let add2_result: f64 = remote_add2.call(&(4.2f64, 0.1f64)).unwrap();
        assert_eq!(add2_result as f64, 4.2f64 + 0.1f64);
    }
}

syringe_test! {
    fn call_procedure_with_large_arg(
        process: Process,
        payload_path: &Path,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = syringe.inject(payload_path).unwrap();

        let mut remote_count_zeros = syringe
            .get_procedure::<[u8; 100], u32>(module, "count_zeros").unwrap()
            .unwrap();
        let mut buffer = [0u8; 100];
        for i in 0..buffer.len() {
            buffer[i] = if i % 2 == 0 { 0u8 } else { 1u8 };
        }
        let count_zeros_result = remote_count_zeros.call(&buffer).unwrap();
        assert_eq!(count_zeros_result, buffer.len() as u32 / 2);
    }
}
