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

## Remote Procedure Calls (RPC)
This crate supports two mechanisms for rpc (both require feature `rpc`).

|                  | `RemotePayloadProcedure`        | `RemoteRawProcedure` |
| ---------------- | ------------------------------ | ------------------------------------------ |
| Feature | `rpc-payload` | `rpc-raw` |
| Argument and Return Requirements | `Serialize + DeserializeOwned` | `Copy`, Argument size has to be smaller than `usize` in target process |
| Function Definition       | Using macro `payload_procedure!` | Any `extern "system"` or `extern "C"` with `#[no_mangle]` |

### RemotePayloadProcedure
A rpc mechanism based on [`bincode`](https://crates.io/crates/bincode).
The target procedure must be defined using the `payload_function!` macro (requires the `rpc-payload-utils` feature).

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

let remote_add = syringe.get_payload_procedure::<fn(f64, f64) -> f64>(injected_payload, "add").unwrap().unwrap();
let result = remote_add.call(&2.0, &4.0).unwrap();
println!("{}", result); // prints 6

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```

### RemoteRawProcedure
This mechanism is based on dynamically generated assembly code.
The target procedure can be any exported function as long as it uses either the `system` or `C` calling convention.
This means that even Win32 functions can be called directly.

The definition of an exported `add` function could look like this:
```rust
#[no_mangle]
extern "system" fn add(a: f64, b: f64) -> f64 {
    a + b
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

let remote_add = syringe.get_raw_procedure::<extern "system" fn(f64, f64) -> f64>(injected_payload, "add").unwrap().unwrap();
let result = remote_add.call(2.0, 4.0).unwrap();
println!("{}", result); // prints 6

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```
