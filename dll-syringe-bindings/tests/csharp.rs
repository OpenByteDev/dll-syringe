#![allow(unexpected_cfgs)]
#![cfg(feature = "csharp")]

mod common;

use std::{path::PathBuf, str::FromStr, process::Command};
use dll_syringe::process::Process;
use path_absolutize::Absolutize;
use common::build_rust_lib;

const NETCORE_VERSION: &str = "net10.0";

pub fn build_csharp_binary() -> PathBuf {
    let project_file_path = PathBuf::from_str("tests/csharp/Test.csproj").unwrap().absolutize().unwrap();
    let dll_path = PathBuf::from_str("tests/csharp/bin/Debug/net10.0/Test.exe").unwrap().absolutize().unwrap();

    let project_path = project_file_path.parent().unwrap();

    Command::new("dotnet")
        .arg("build")
        .arg(&project_file_path)
        .arg("--framework")
        .arg(NETCORE_VERSION)
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
        build_rust_lib();
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
