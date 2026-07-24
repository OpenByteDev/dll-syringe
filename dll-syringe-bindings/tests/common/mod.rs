mod other;
pub use other::*;

use std::{
    env,
    path::PathBuf,
    process::{Command, ExitStatus},
};

fn env_var_path(key: &str) -> PathBuf {
    let s = env::var_os(key).expect(&format!("env var {key} not found"));
    PathBuf::from(s)
}

#[allow(unused)]
pub fn build_rust_lib() -> PathBuf {
    // Build lib
    let target = if cfg!(target_arch = "x86_64") {
        "x86_64-pc-windows-msvc"
    } else {
        "i686-pc-windows-msvc"
    };
    let is_debug = cfg!(debug_assertions);
    let profile = if is_debug { "debug" } else { "release" };
    let cargo = env_var_path("CARGO");
    let mut command = Command::new(cargo);
    command
        .arg("build")
        .arg("--lib")
        .arg("--target")
        .arg(target);
    if !is_debug {
        command.arg("--release");
    }
    let build_status: ExitStatus = command.status().expect("Failed to run cargo build");
    assert!(build_status.success());

    // Get lib path
    let manifest_dir = env_var_path("CARGO_MANIFEST_DIR");
    let build_dir = manifest_dir.join("target").join(target).join(profile);
    build_dir.join("dll_syringe_bindings.lib")
}
