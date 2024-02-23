#![cfg(feature = "syringe")]

use dll_syringe::{error::EjectError, process::Process, Syringe};

#[allow(unused)]
mod common;

syringe_test! {
    fn eject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_suspended_process(process).unwrap();
        let module = syringe.inject(payload_path).unwrap();
        syringe.eject(module).unwrap();
    }
}

syringe_test! {
    fn eject_with_crashed_process_fails_with_process_inaccessible(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_suspended_process(process).unwrap();
        let module = syringe.inject(payload_path).unwrap();

        syringe.process().kill().unwrap();

        let result = syringe.eject(module);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EjectError::ProcessInaccessible), "{err:?}");
    }
}
