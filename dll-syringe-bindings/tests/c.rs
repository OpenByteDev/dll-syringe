#![allow(unexpected_cfgs)]
#![cfg(feature = "c")]

mod common;

use std::{path::{Path, PathBuf}, process::Command};
use dll_syringe::process::Process;
use common::build_rust_lib;

fn build_c_binary(lib_path: &Path) -> PathBuf {
    let out_dir = lib_path.parent().unwrap();
    let test_bin = out_dir.join("c_test.exe");

    let arch = if cfg!(target_arch = "x86_64") { "x86_64" } else { "i686" };
    let mut cl = find_msvc_tools::find(arch, "cl.exe").unwrap();
    cl.arg("tests/c/main.c")
      .arg("ws2_32.lib").arg("ntdll.lib")
      .arg(lib_path)
      .arg(format!("/Fe:{}", test_bin.display()))
      .arg(format!("/Fo:{}/", out_dir.display()));
    let compile_status = cl.status().unwrap();
    assert!(compile_status.success());

    test_bin
}

syringe_test! {
    fn inject_from_c(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let lib_path = build_rust_lib();
        let c_bin_path = build_c_binary(&lib_path);

        // Execute c program
        let pid = process.pid().unwrap().to_string();
        let run_status = Command::new(&c_bin_path)
            .arg(pid)
            .arg(payload_path)
            .status()
            .expect("Failed to run C executable");
        
        assert!(run_status.success());
    }
}
