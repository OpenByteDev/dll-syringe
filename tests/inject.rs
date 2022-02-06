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
fn inject_32() -> Result<(), Box<dyn Error>> {
    inject_test(
        common::build_test_payload_x86()?,
        common::build_test_target_x86()?,
    )
}

#[test]
#[cfg(target_arch = "x86_64")]
fn inject_64() -> Result<(), Box<dyn Error>> {
    inject_test(
        common::build_test_payload_x64()?,
        common::build_test_target_x64()?,
    )
}

fn inject_test(
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

    let mut syringe = Syringe::for_process(&dummy_process);
    syringe.inject(payload_path)?;

    Ok(())
}
