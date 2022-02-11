use dll_syringe::{Process, Syringe, error::SyringeError};
use std::{
    error::Error,
    path::Path,
    process::{Command, Stdio},
};

#[allow(unused)]
mod common;

#[test]
#[cfg(any(
    target_arch = "x86",
    all(target_arch = "x86_64", feature = "into_x86_from_x64")
))]
fn inject_with_valid_path_succeeds_32() -> Result<(), Box<dyn Error>> {
    inject_with_valid_path_succeeds(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(any(
    target_arch = "x86",
    all(target_arch = "x86_64", feature = "into_x86_from_x64")
))]
fn inject_with_invalid_path_fails_with_remote_io_32() -> Result<(), Box<dyn Error>> {
    inject_with_invalid_path_fails_with_remote_io(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(any(
    target_arch = "x86",
    all(target_arch = "x86_64", feature = "into_x86_from_x64")
))]
fn inject_with_crashed_process_fails_with_io_32() -> Result<(), Box<dyn Error>> {
    inject_with_crashed_process_fails_with_io(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn inject_with_valid_path_succeeds_64() -> Result<(), Box<dyn Error>> {
    inject_with_valid_path_succeeds(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn inject_with_invalid_path_fails_with_remote_io_64() -> Result<(), Box<dyn Error>> {
    inject_with_invalid_path_fails_with_remote_io(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn inject_with_crashed_process_fails_with_io_64() -> Result<(), Box<dyn Error>> {
    inject_with_crashed_process_fails_with_io(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

fn inject_with_valid_path_succeeds(
    payload_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> Result<(), Box<dyn Error>> {
    let dummy_process: Process = Command::new(target_path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .into();
    let dummy_process_clone = dummy_process.try_clone().unwrap();
    let _guard = dispose::defer(|| {
        if dummy_process.is_alive() {
            dummy_process_clone.kill().unwrap();
        }
    });

    let mut syringe = Syringe::for_process(&dummy_process);
    syringe.inject(payload_path)?;

    Ok(())
}

fn inject_with_invalid_path_fails_with_remote_io(
    _payload_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> Result<(), Box<dyn Error>> {
    let dummy_process: Process = Command::new(target_path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .into();
    let dummy_process_clone = dummy_process.try_clone().unwrap();
    let _guard = dispose::defer(|| {
        if dummy_process.is_alive() {
            dummy_process_clone.kill().unwrap();
        }
    });

    let mut syringe = Syringe::for_process(&dummy_process);
    let result = syringe.inject("invalid path");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SyringeError::RemoteIo(_)));
    let io_err = match err { SyringeError::RemoteIo(io_err) => io_err, _ => unreachable!() };
    assert_eq!(io_err.raw_os_error(), Some(126));

    Ok(())
}

fn inject_with_crashed_process_fails_with_io(
    payload_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> Result<(), Box<dyn Error>> {
    let dummy_process: Process = Command::new(target_path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .into();
    let dummy_process_clone = dummy_process.try_clone().unwrap();
    let _guard = dispose::defer(|| {
        if dummy_process.is_alive() {
            dummy_process_clone.kill().unwrap();
        }
    });

    let mut syringe = Syringe::for_process(&dummy_process);
    dummy_process.clone().kill().unwrap();

    let result = syringe.inject(payload_path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, SyringeError::ProcessInaccessible));

    Ok(())
}


