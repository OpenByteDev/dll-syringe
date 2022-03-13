A crate for DLL injection on windows.

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
The target procedure must be defined using the [`payload_procedure`] macro (requires the "payload-utils" feature).

The definition of an exported `add` function could look like this:
```rust
dll_syringe::payload_function! {
    fn add(a: f64, b: f64) -> f64 {
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
