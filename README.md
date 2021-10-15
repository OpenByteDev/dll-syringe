# dll-syringe

[![CI](https://github.com/OpenByteDev/dll-syringe/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenByteDev/dll-syringe/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/dll-syringe.svg)](https://crates.io/crates/dll-syringe)
[![Documentation](https://docs.rs/dll-syringe/badge.svg)](https://docs.rs/dll-syringe)
[![dependency status](https://deps.rs/repo/github/openbytedev/dll-syringe/status.svg)](https://deps.rs/repo/github/openbytedev/dll-syringe)
[![MIT](https://img.shields.io/crates/l/dll-syringe.svg)](https://github.com/OpenByteDev/dll-syringe/blob/master/LICENSE)

A windows dll injection library written in Rust.

## Supported scenarios
| Injector Process | Target Process | Supported?                                 |
| ---------------- | -------------- | ------------------------------------------ |
| 32-bit           | 32-bit         | Yes                                        |
| 32-bit           | 64-bit         | No                                         |
| 64-bit           | 32-bit         | Yes (requires feature `into_x86_from_x64`) |
| 64-bit           | 64-bit         | Yes                                        |

## Example
```rust no_run
use dll_syringe::{Syringe, Process};

// find target process by name
let target_process = Process::find_first_by_name("target_process").unwrap();

// create new syringe (reuse for better performance)
let syringe = Syringe::new();

// inject the payload into the target process
let injected_payload = syringe.inject(&target_process, "injection_payload.dll").unwrap();

// do something else

// eject the payload from the target (this is optional)
injected_payload.eject().unwrap();
```

## License
Licensed under MIT license ([LICENSE](https://github.com/OpenByteDev/dll-syringe/blob/master/LICENSE) or http://opensource.org/licenses/MIT)
