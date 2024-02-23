# Navigate up one folder from the current script location
Set-Location "$PSScriptRoot\.."

# Windows/MSVC x86
cargo test --target i686-pc-windows-msvc -- --nocapture

# Windows/MSVC x64
cargo test --target x86_64-pc-windows-msvc -- --nocapture