use core::iter::once;
use dll_syringe::process::OwnedProcess;
use dll_syringe::process::Process;
use std::ffi::CString;
use std::ffi::OsStr;
use std::mem::zeroed;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::prelude::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::{
    env::{current_dir, var},
    error::Error,
    fs::{canonicalize, remove_file, File},
    io::{copy, ErrorKind},
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Mutex,
};
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::CREATE_SUSPENDED;

pub fn build_test_payload_x86() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_payload", &find_x86_variant_of_target(), false, "dll")
}

pub fn build_test_target_x86() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_target", &find_x86_variant_of_target(), false, "exe")
}

pub fn build_test_payload_x64() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_payload", &find_x64_variant_of_target(), false, "dll")
}

pub fn build_test_target_x64() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_target", &find_x64_variant_of_target(), false, "exe")
}

fn find_x64_variant_of_target() -> String {
    current_platform::CURRENT_PLATFORM.replace("i686", "x86_64")
}

fn find_x86_variant_of_target() -> String {
    current_platform::CURRENT_PLATFORM.replace("x86_64", "i686")
}

pub fn build_helper_crate(
    crate_name: &str,
    target: &str,
    release: bool,
    ext: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let payload_crate_path = PathBuf::from_str(".\\tests\\helpers")?
        .join(crate_name)
        .canonicalize()?;

    // For cross/wine testing, we precompile in external script.
    if !is_cross() {
        let mut command = Command::new("cargo");
        command
            .arg("build")
            .arg("--target")
            .arg(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let exit_code = command.current_dir(&payload_crate_path).spawn()?.wait()?;
        assert!(
            exit_code.success(),
            "Failed to build helper crate {} for target {}",
            crate_name,
            target
        );
    }

    let mut payload_artifact_path = payload_crate_path;
    payload_artifact_path.push("target");
    payload_artifact_path.push(target);
    payload_artifact_path.push(if release { "release" } else { "debug" });
    payload_artifact_path.push(format!("{crate_name}.{ext}"));
    assert!(
        &payload_artifact_path.exists(),
        "Artifact doesn't exist! {:?}",
        &payload_artifact_path
    );

    Ok(payload_artifact_path)
}

/// Detects cross-rs.
///
/// Remarks:
///
/// I wish I could install Rust itself via `Rustup` here, but the Ubuntu image that ships with
/// `cross` doesn't have the right packages to support encryption, thus we can't download toolchains
/// (I tried). And I also didn't have good luck with pre-build step and downloading extra packages.
///
/// So as a compromise, we build the test binaries outside for testing from Linux.
fn is_cross() -> bool {
    var("CROSS_SYSROOT").is_ok()
}

pub(crate) fn start_suspended_process(path: &Path) -> OwnedProcess {
    unsafe {
        let mut startup_info: STARTUPINFOW = zeroed();
        let mut process_info: PROCESS_INFORMATION = zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let target_path_wide: Vec<u16> = OsStr::new(path.to_str().unwrap())
            .encode_wide()
            .chain(once(0)) // null terminator
            .collect();

        if CreateProcessW(
            target_path_wide.as_ptr(),
            null_mut(),       // Command line
            null_mut(),       // Process security attributes
            null_mut(),       // Thread security attributes
            0,                // Inherit handles
            CREATE_SUSPENDED, // Creation flags
            null_mut(),       // Environment
            null_mut(),       // Current directory
            &mut startup_info,
            &mut process_info,
        ) == 0
        {
            panic!("Failed to create suspended process");
        } else {
            OwnedProcess::from_handle_unchecked(OwnedHandle::from_raw_handle(process_info.hProcess))
        }
    }
}

#[macro_export]
macro_rules! syringe_test {
    (fn $test_name:ident ($process:ident : OwnedProcess, $payload_path:ident : &Path $(,)?) $body:block) => {
        mod $test_name {
            use super::*;
            use dll_syringe::process::OwnedProcess;
            use std::{
                path::Path,
            };
            use $crate::common::start_suspended_process;

            #[test]
            #[cfg(any(
                target_arch = "x86",
                all(target_arch = "x86_64", feature = "into-x86-from-x64")
            ))]
            fn x86() {
                test_with_setup(
                    common::build_test_payload_x86().unwrap(),
                    common::build_test_target_x86().unwrap(),
                )
            }

            #[test]
            #[cfg(target_arch = "x86_64")]
            fn x86_64() {
                test_with_setup(
                    common::build_test_payload_x64().unwrap(),
                    common::build_test_target_x64().unwrap(),
                )
            }

            fn test_with_setup(
                payload_path: impl AsRef<Path>,
                target_path: impl AsRef<Path>,
            ) {
                let proc = start_suspended_process(target_path.as_ref());
                let _guard = proc.try_clone().unwrap().kill_on_drop();
                test(proc, payload_path.as_ref());
            }

            fn test(
                $process : OwnedProcess,
                $payload_path : &Path,
            ) $body
        }
    };
}

#[macro_export]
macro_rules! suspended_process_test {
    (fn $test_name:ident ($process:ident : OwnedProcess $(,)?) $body:block) => {
        mod $test_name {
            use super::*;
            use dll_syringe::process::OwnedProcess;
            use std::{
                path::Path
            };
            use $crate::common::start_suspended_process;

            #[test]
            #[cfg(any(
                target_arch = "x86",
                all(target_arch = "x86_64", feature = "into-x86-from-x64")
            ))]
            fn x86() {
                test_with_setup(
                    common::build_test_target_x86().unwrap(),
                )
            }

            #[test]
            #[cfg(target_arch = "x86_64")]
            fn x86_64() {
                test_with_setup(
                    common::build_test_target_x64().unwrap(),
                )
            }

            fn test_with_setup(
                target_path: impl AsRef<Path>,
            ) {
                let proc = start_suspended_process(target_path.as_ref());
                let _guard = proc.try_clone().unwrap().kill_on_drop();
                test(proc)
            }

            fn test(
                $process : OwnedProcess,
            ) $body
        }
    };
}

#[macro_export]
macro_rules! process_test {
    (fn $test_name:ident ($process:ident : OwnedProcess $(,)?) $body:block) => {
        mod $test_name {
            use super::*;
            use dll_syringe::process::OwnedProcess;
            use std::{
                path::Path,
                process::Command,
                process::Stdio,
            };

            #[test]
            #[cfg(any(
                target_arch = "x86",
                all(target_arch = "x86_64", feature = "into-x86-from-x64")
            ))]
            fn x86() {
                test_with_setup(
                    common::build_test_target_x86().unwrap(),
                )
            }

            #[test]
            #[cfg(target_arch = "x86_64")]
            fn x86_64() {
                test_with_setup(
                    common::build_test_target_x64().unwrap(),
                )
            }

            fn test_with_setup(
                target_path: impl AsRef<Path>,
            ) {
                let dummy_process: OwnedProcess = Command::new(target_path.as_ref())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
                    .into();

                let _guard = dummy_process.try_clone().unwrap().kill_on_drop();
                test(dummy_process)
            }

            fn test(
                $process : OwnedProcess,
            ) $body
        }
    };
}
