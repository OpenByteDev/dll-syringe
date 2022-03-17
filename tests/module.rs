use dll_syringe::{process::Process, Syringe};
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

#[cfg(feature = "syringe")]
syringe_test! {
    fn guess_is_loaded_returns_true_after_inject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();
        assert!(module.guess_is_loaded());
    }
}

#[cfg(feature = "syringe")]
syringe_test! {
    fn guess_is_loaded_returns_false_after_eject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();
        syringe.eject(module).unwrap();
        assert!(!module.try_guess_is_loaded().unwrap());
    }
}

#[cfg(feature = "syringe")]
syringe_test! {
    fn guess_is_loaded_returns_false_after_kill(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();
        syringe.process().kill().unwrap();
        assert!(!module.try_guess_is_loaded().unwrap());
    }
}
