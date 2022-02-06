#![cfg(feature = "remote_procedure")]

use dll_syringe::{Process, Syringe};
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
fn get_procedure_address_32() -> Result<(), Box<dyn Error>> {
    get_procedure_address_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn get_procedure_address_64() -> Result<(), Box<dyn Error>> {
    get_procedure_address_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

fn get_procedure_address_test(
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
        if dummy_process_clone.is_alive() {
            dummy_process_clone.kill().unwrap();
        }
    });

    let mut syringe = Syringe::for_process(&dummy_process);
    let module = syringe.inject(payload_path)?;

    let dll_main = syringe.get_procedure_address(module, "DllMain")?;
    assert!(dll_main.is_some());

    let open_process = syringe.get_procedure_address(
        dummy_process.find_module_by_name("kernel32.dll")?.unwrap(),
        "OpenProcess",
    )?;
    assert!(open_process.is_some());

    let invalid = syringe.get_procedure_address(module, "ProcedureThatDoesNotExist")?;
    assert!(invalid.is_none());

    Ok(())
}

#[test]
#[cfg(any(
    target_arch = "x86",
    all(target_arch = "x86_64", feature = "into_x86_from_x64")
))]
fn call_procedure_32() -> Result<(), Box<dyn Error>> {
    call_procedure_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn call_procedure_64() -> Result<(), Box<dyn Error>> {
    call_procedure_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

fn call_procedure_test(
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
        if dummy_process_clone.is_alive() {
            dummy_process_clone.kill().unwrap();
        }
    });

    let mut syringe = Syringe::for_process(&dummy_process);
    let module = syringe.inject(payload_path)?;

    // Simple echo test
    let remote_echo2 = syringe.get_procedure(module, "echo2")?;
    assert!(remote_echo2.is_some());
    let mut remote_echo2 = remote_echo2.unwrap();
    let echo2_result: u32 = remote_echo2.call(&0x1234_5678u32)?;
    assert_eq!(echo2_result, 0x1234_5678u32);

    // "Complex" addition test
    let mut remote_add = syringe.get_procedure(module, "add")?.unwrap();

    let add_result: f64 = remote_add.call(&(4.2f64, 0.1f64))?;
    assert_eq!(add_result as f64, 4.2f64 + 0.1f64);

    Ok(())
}
