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

## Usage
### Inject & Eject
The example below will inject and then eject the module at the path "injection_payload.dll" into the process called "ExampleProcess".

```rust no_run
use dll_syringe::{Syringe, Process};

// find target process by name
let target_process = Process::find_first_by_name("ExampleProcess").unwrap();

// create a new syringe for the target process
let mut syringe = Syringe::for_process(&target_process);

// inject the payload into the target process
let injected_payload = syringe.inject("injection_payload.dll").unwrap();

// do something else

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```

## Call Remote Procedures
The example below will perform the same injection as above, but will call the `add` function defined exported from the injected module.

The definition of the exported `add` function looks like this.
```rust no_run
#[no_mangle]
extern "system" fn add(numbers: *const (f64, f64), result: *mut f64) {
    unsafe { *result = (*numbers).0 + (*numbers).1 }
}
```

The code of the injector/caller will look like this.
```rust no_run
use dll_syringe::{Syringe, Process};

// find target process by name
let target_process = Process::find_first_by_name("Name of target process").unwrap();

// create a new syringe for the target process
let mut syringe = Syringe::for_process(&target_process);

// inject the payload into the target process
let injected_payload = syringe.inject("Path to injection payload").unwrap();

let result: f64 = syringe.get_procedure(injected_payload, "add").unwrap().unwrap().call(&(2f64, 4f64)).unwrap();
println!("{}", result); // prints 6

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```

Note that currently only functions with a signature of `extern "system" fn(args: *mut A, result: *mut B) -> ()` are supported. When the payload and the procedure are compiled for a different target architecture the passed types have to have the same size.


## License
Licensed under MIT license ([LICENSE](https://github.com/OpenByteDev/dll-syringe/blob/master/LICENSE) or http://opensource.org/licenses/MIT)

## Attribution
Inspired by [Reloaded.Injector](https://github.com/Reloaded-Project/Reloaded.Injector) from [Sewer](https://github.com/Sewer56).
