#![feature(try_blocks)]

use dll_syringe::{Process, Syringe};
use std::{
    error::Error,
    path::Path,
    process::{Command, Stdio},
    ptr,
};
use winapi::shared::minwindef::{DWORD, LPVOID};

#[allow(unused)]
mod common;

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "call_remote_procedure")]
fn get_procedure_address_32() -> Result<(), Box<dyn Error>> {
    get_procedure_address_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "call_remote_procedure")]
fn get_procedure_address_64() -> Result<(), Box<dyn Error>> {
    get_procedure_address_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

#[cfg(feature = "call_remote_procedure")]
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
        dummy_process_clone.kill().unwrap();
    });

    let syringe = Syringe::new();
    let module = syringe.inject(&dummy_process, payload_path.as_ref())?;

    let dll_main = syringe.get_procedure_address(module, "DllMain")?;
    assert_ne!(dll_main, ptr::null());

    let open_process = syringe.get_procedure_address(
        dummy_process.find_module_by_name("kernel32.dll")?.unwrap(),
        "OpenProcess",
    )?;
    assert_ne!(open_process, ptr::null());

    Ok(())
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "call_remote_procedure")]
fn call_procedure_fast_32() -> Result<(), Box<dyn Error>> {
    call_procedure_fast_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "call_remote_procedure")]
fn call_procedure_fast_64() -> Result<(), Box<dyn Error>> {
    call_procedure_fast_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

#[cfg(feature = "call_remote_procedure")]
fn call_procedure_fast_test(
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
        dummy_process_clone.kill().unwrap();
    });

    let syringe = Syringe::new();
    let module = syringe.inject(&dummy_process, payload_path.as_ref())?;

    let remote_echo = syringe.get_procedure_address(module, "echo")?;
    assert_ne!(remote_echo, ptr::null());

    let echo_value = 0x1234_5678_9abc_def0u64 as LPVOID;
    let echo_result =
        unsafe { syringe.call_procedure_fast(&dummy_process, remote_echo, echo_value) }?;
    assert_eq!(echo_value as DWORD, echo_result);

    Ok(())
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "call_remote_procedure")]
fn call_procedure_32() -> Result<(), Box<dyn Error>> {
    call_procedure_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
#[cfg(feature = "call_remote_procedure")]
fn call_procedure_64() -> Result<(), Box<dyn Error>> {
    call_procedure_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

#[cfg(feature = "call_remote_procedure")]
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

    let syringe = Syringe::new();
    let module = syringe.inject(&dummy_process, payload_path.as_ref())?;

    let remote_echo2 = syringe.get_procedure_address(module, "echo2")?;
    assert_ne!(remote_echo2, ptr::null());

    let echo2_result: u32 =
        unsafe { syringe.call_procedure(&dummy_process, remote_echo2, &0x1234_5678u32) }?;
    assert_eq!(echo2_result, 0x1234_5678u32);

    let remote_add = syringe.get_procedure_address(module, "add")?;
    assert_ne!(remote_add, ptr::null());

    let add_result: f64 =
        unsafe { syringe.call_procedure(&dummy_process, remote_add, &(4.2f64, 0.1f64)) }?;
    assert_eq!(add_result as f64, 4.2f64 + 0.1f64);

    Ok(())
}
