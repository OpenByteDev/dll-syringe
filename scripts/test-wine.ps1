# Navigate up one folder from the current script location
Set-Location "$PSScriptRoot\.."

# Testing
$env:CROSS_SYSROOT = "." # pretend we cross

# Prebuild dummy projects.
cargo +nightly xwin rustc --manifest-path "tests/helpers/test_target/Cargo.toml" --target i686-pc-windows-msvc --xwin-arch x86 --xwin-cache-dir "target/cache/x86"
cargo +nightly xwin rustc --manifest-path "tests/helpers/test_payload/Cargo.toml" --target i686-pc-windows-msvc --xwin-arch x86 --xwin-cache-dir "target/cache/x86"
cargo +nightly xwin rustc --manifest-path "tests/helpers/test_target/Cargo.toml" --target x86_64-pc-windows-msvc --xwin-arch x86_64 --xwin-cache-dir "target/cache/x64"
cargo +nightly xwin rustc --manifest-path "tests/helpers/test_payload/Cargo.toml" --target x86_64-pc-windows-msvc --xwin-arch x86_64 --xwin-cache-dir "target/cache/x64"

# Windows/MSVC x86
cargo +nightly xwin test --target i686-pc-windows-msvc --xwin-arch x86 --xwin-cache-dir "target/cache/x86"

# Windows/MSVC x64
cargo +nightly xwin test --target x86_64-pc-windows-msvc --xwin-arch x86_64 --xwin-cache-dir "target/cache/x64"