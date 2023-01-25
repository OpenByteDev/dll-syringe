#![cfg(feature = "syringe")]

use dll_syringe::{error::InjectError, process::Process, Syringe};

#[allow(unused)]
mod common;

syringe_test! {
    fn inject_with_valid_path_succeeds(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        syringe.inject(payload_path).unwrap();
    }
}

process_test! {
    fn inject_with_invalid_path_fails_with_remote_io(
        process: OwnedProcess,
    ) {
        let syringe = Syringe::for_process(process);
        let result = syringe.inject("invalid path");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, InjectError::RemoteIo(_)));
        let io_err = match err {
            InjectError::RemoteIo(io_err) => io_err,
            _ => unreachable!(),
        };
        assert_eq!(io_err.raw_os_error(), Some(126));
    }
}

syringe_test! {
    fn inject_with_crashed_process_fails_with_process_inaccessible(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        syringe.process().kill().unwrap();

        let result = syringe.inject(payload_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, InjectError::ProcessInaccessible), "{err:?}");
    }
}

mod inject_with_wrong_payload_fails_with_module_incompatible {
    use super::*;
    use dll_syringe::process::OwnedProcess;
    use std::{
        path::Path,
        process::{Command, Stdio},
    };

    #[test]
    #[cfg(target_arch = "x86")]
    fn x86() {
        test_with_setup(
            common::build_test_payload_x64().unwrap(),
            common::build_test_target_x86().unwrap(),
        )
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_64() {
        test_with_setup(
            common::build_test_payload_x86().unwrap(),
            common::build_test_target_x64().unwrap(),
        )
    }

    fn test_with_setup(payload_path: impl AsRef<Path>, target_path: impl AsRef<Path>) {
        let dummy_process: OwnedProcess = Command::new(target_path.as_ref())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
            .into();

        let _guard = dummy_process.try_clone().unwrap().kill_on_drop();

        test(dummy_process, payload_path.as_ref())
    }

    fn test(process: OwnedProcess, payload_path: &Path) {
        let syringe = Syringe::for_process(process);

        let result = syringe.inject(payload_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, InjectError::ArchitectureMismatch), "{err:?}");
    }
}
