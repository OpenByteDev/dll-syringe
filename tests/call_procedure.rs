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
    let remote_echo = syringe.get_procedure(module, "echo")?;
    assert!(remote_echo.is_some());
    let mut remote_echo = remote_echo.unwrap();
    let echo_result: u32 = remote_echo.call(&0x1234_5678u32)?;
    assert_eq!(echo_result, 0x1234_5678u32);

    // "Complex" addition test
    let mut remote_add = syringe.get_procedure(module, "add")?.unwrap();
    let add_result: f64 = remote_add.call(&(4.2f64, 0.1f64))?;
    assert_eq!(add_result as f64, 4.2f64 + 0.1f64);

    // "Complex" addition test with dll-syringe-payload-utils
    let mut remote_add2 = syringe.get_procedure(module, "add2")?.unwrap();
    let add2_result: f64 = remote_add2.call(&(4.2f64, 0.1f64))?;
    assert_eq!(add2_result as f64, 4.2f64 + 0.1f64);

    // Complex addition test larger argument
    let mut remote_count_zeros = syringe.get_procedure::<[u8; 100], u32, _>(module, "count_zeros")?.unwrap();
    let mut buffer = [0u8; 100];
    for i in 0..buffer.len() {
        buffer[i] = if i % 2 == 0 { 0u8 } else { 1u8 };
    }
    let count_zeros_result = remote_count_zeros.call(&buffer)?;
    assert_eq!(count_zeros_result, buffer.len() as u32 / 2);

    Ok(())
}
