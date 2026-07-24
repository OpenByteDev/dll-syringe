#![allow(unexpected_cfgs)]
#![cfg(feature = "csharp")]

mod common;

use common::build_rust_lib;
use dll_syringe::process::Process;
use path_absolutize::Absolutize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

const NETCORE_VERSION: &str = "net10.0";

// Copy rust dll to where c# expects it
fn stage_native_lib(lib_path: &Path) {
    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        "x86"
    };
    let native_dll_path = lib_path.parent().unwrap().join("dll_syringe_bindings.dll");
    let runtimes_dir = PathBuf::from_str(&format!("bindings/csharp/runtimes/win-{arch}/native"))
        .unwrap()
        .absolutize()
        .unwrap();
    fs::create_dir_all(&runtimes_dir).expect("Failed to create runtimes dir");
    fs::copy(
        &native_dll_path,
        runtimes_dir.join("dll-syringe.native.dll"),
    )
    .expect("Failed to copy native dll into runtimes dir");
}

pub fn build_csharp_binary() -> PathBuf {
    let project_file_path = PathBuf::from_str("tests/csharp/Test.csproj")
        .unwrap()
        .absolutize()
        .unwrap();
    let dll_path = PathBuf::from_str("tests/csharp/bin/Debug/net10.0/Test.exe")
        .unwrap()
        .absolutize()
        .unwrap();

    let project_path = project_file_path.parent().unwrap();
    let platform_target = if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        "x86"
    };

    Command::new("dotnet")
        .arg("build")
        .arg(&project_file_path)
        .arg("--framework")
        .arg(NETCORE_VERSION)
        .arg(format!("-p:PlatformTarget={platform_target}"))
        .current_dir(project_path)
        .spawn()
        .expect("dotnet build failed")
        .wait()
        .expect("dotnet build failed");

    dll_path
}

syringe_test! {
    fn inject_from_csharp(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let lib_path = build_rust_lib();
        stage_native_lib(&lib_path);
        let csharp_bin_path = build_csharp_binary();

        // Execute c# program
        let pid = process.pid().unwrap().to_string();
        let run_status = Command::new(&csharp_bin_path)
            .arg(pid)
            .arg(payload_path)
            .status()
            .expect("Failed to run C# executable");

        assert!(run_status.success());
    }
}
