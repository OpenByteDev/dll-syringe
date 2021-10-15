#![feature(try_blocks)]

use dll_syringe::{Process, Syringe};
use std::{
    error::Error,
    path::Path,
    process::{Command, Stdio},
};

mod common;

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn eject_32_from_32() -> Result<(), Box<dyn Error>> {
    eject_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn eject_64_from_64() -> Result<(), Box<dyn Error>> {
    eject_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

fn eject_test(
    payload_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
) -> Result<(), Box<dyn Error>> {
    let dummy_process: Process = Command::new(target_path.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .into();

    let syringe = Syringe::new();
    let module = syringe.inject(&dummy_process, payload_path.as_ref())?;
    module.eject()?;

    dummy_process.kill()?;

    Ok(())
}
