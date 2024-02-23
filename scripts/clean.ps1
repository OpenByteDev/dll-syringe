# Navigate up one folder from the current script location
Set-Location "$PSScriptRoot\.."
cargo clean

Set-Location "./tests/helpers/test_payload"
cargo clean
Set-Location "../../.."

Set-Location "./tests/helpers/test_target"
cargo clean
Set-Location "../../.."
