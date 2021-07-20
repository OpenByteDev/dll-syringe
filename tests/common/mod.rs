use std::{error::Error, path::PathBuf, process::Command, str::FromStr};

pub fn build_test_payload_x86() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_payload", Some("i686-pc-windows-msvc"), false, "dll")
}

pub fn build_test_target_x86() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_target", Some("i686-pc-windows-msvc"), false, "exe")
}

pub fn build_test_payload_x64() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_payload", Some("x86_64-pc-windows-msvc"), false, "dll")
}

pub fn build_test_target_x64() -> Result<PathBuf, Box<dyn Error>> {
    build_helper_crate("test_target", Some("x86_64-pc-windows-msvc"), false, "exe")
}

pub fn build_helper_crate(
    crate_name: &str,
    target: Option<&str>,
    release: bool,
    ext: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let payload_crate_path = PathBuf::from_str(".\\tests\\helpers")?
        .join(crate_name)
        .canonicalize()?;

    let mut command = Command::new("cargo");
    command.arg("build");
    if let Some(target) = target {
        command.arg("--target").arg(target);
    }
    command.current_dir(&payload_crate_path).spawn()?.wait()?;

    let mut payload_artifact_path = payload_crate_path;
    payload_artifact_path.push("target");

    if let Some(target) = target {
        payload_artifact_path.push(target);
    }

    payload_artifact_path.push(if release { "release" } else { "debug" });
    payload_artifact_path.push(format!("{}.{}", crate_name, ext));
    assert!(&payload_artifact_path.exists());

    Ok(payload_artifact_path)
}
