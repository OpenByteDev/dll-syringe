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
| 64-bit           | 32-bit         | Yes (requires feature `into-x86-from-x64`) |
| 64-bit           | 64-bit         | Yes                                        |

## Usage
### Inject & Eject
This crate allows you to inject and eject a DLL into a target process.
The example below will inject and then eject `injection_payload.dll` into the process called "ExampleProcess".

```rust no_run
use dll_syringe::{Syringe, process::OwnedProcess};

// find target process by name
let target_process = OwnedProcess::find_first_by_name("ExampleProcess").unwrap();

// create a new syringe for the target process
let syringe = Syringe::for_process(target_process);

// inject the payload into the target process
let injected_payload = syringe.inject("injection_payload.dll").unwrap();

// do something else

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```

## Calling Remote Procedures
A simple rpc mechanism based in [`bincode`](https://crates.io/crates/bincode) is supported with the "rpc" feature.
The target procedure must be defined using the `payload_function!` macro (requires the "payload-utils" feature).

The definition of an exported `add` function could look like this:
```rust
dll_syringe::payload_function! {
    fn add(a: f64, b: f64) -> f64) {
        a + b
    }
}
```

The code of the injector/caller could looks like this:
```rust no_run
use dll_syringe::{Syringe, process::OwnedProcess};

// find target process by name
let target_process = OwnedProcess::find_first_by_name("ExampleProcess").unwrap();

// create a new syringe for the target process
let syringe = Syringe::for_process(target_process);

// inject the payload into the target process
let injected_payload = syringe.inject("injection_payload.dll").unwrap();

let remote_add = syringe.get_procedure::<fn(f64, f64) -> f64>(injected_payload, "add").unwrap().unwrap();
let result = remote_add.call(&2.0, &4.0).unwrap();
println!("{}", result); // prints 6

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```


## License
Licensed under MIT license ([LICENSE](https://github.com/OpenByteDev/dll-syringe/blob/master/LICENSE) or http://opensource.org/licenses/MIT)

## Attribution
Inspired by [Reloaded.Injector](https://github.com/Reloaded-Project/Reloaded.Injector) from [Sewer](https://github.com/Sewer56).
