use dll_syringe::process::Process;
use std::time::Duration;

#[allow(unused)]
mod common;

process_test! {
    fn path_returns_correct_path(
        process: OwnedProcess
    ) {
        let path = process.path().unwrap();
        let main_module = process.borrowed().wait_for_module_by_path(&path, Duration::from_secs(1)).unwrap().unwrap();
        assert!(same_file::is_same_file(path, main_module.path().unwrap()).unwrap());
    }
}

process_test! {
    fn base_name_returns_correct_path(
        process: OwnedProcess
    ) {
        let base_name = process.base_name().unwrap();
        let main_module = process.borrowed().wait_for_module_by_name(&base_name, Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(base_name, main_module.base_name().unwrap());
    }
}
