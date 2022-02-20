A crate for DLL injection on windows.

## Supported scenarios
| Injector Process | Target Process | Supported?                                 |
| ---------------- | -------------- | ------------------------------------------ |
| 32-bit           | 32-bit         | Yes                                        |
| 32-bit           | 64-bit         | No                                         |
| 64-bit           | 32-bit         | Yes (requires feature `into_x86_from_x64`) |
| 64-bit           | 64-bit         | Yes                                        |

## Usage
### Inject & Eject
The example below will inject and then eject the module at the path `injection_payload.dll` into the process called "ExampleProcess".

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
The example below will perform the same injection as above, but will call the `add` function defined exported from the injected module.

The definition of the exported `add` function looks like this.
```rust no_run
#[no_mangle]
pub extern "system" fn add(numbers: *const (f64, f64), result: *mut f64) {
    unsafe { *result = (*numbers).0 + (*numbers).1 }
}
```

The code of the injector/caller will look like this.
```rust no_run
use dll_syringe::{Syringe, process::OwnedProcess};

// find target process by name
let target_process = OwnedProcess::find_first_by_name("ExampleProcess").unwrap();

// create a new syringe for the target process
let syringe = Syringe::for_process(target_process);

// inject the payload into the target process
let injected_payload = syringe.inject("injection_payload.dll").unwrap();

let result = syringe.get_procedure::<(f64, f64), f64>(injected_payload, "add").unwrap().unwrap().call(&(2.0, 4.0)).unwrap();
println!("{}", result); // prints 6

// eject the payload from the target (optional)
syringe.eject(injected_payload).unwrap();
```

Note that currently only functions with a signature of `extern "system" fn(args: *mut A, result: *mut B) -> ()` are supported. When the payload and the procedure are compiled for a different target architecture the passed types have to have the same size.

The definition of the exported function above can be simplified using [`dll-syringe-payload-utils`](https://docs.rs/dll-syringe-payload-utils/latest/dll_syringe_payload_utils/):
```rust
dll_syringe_payload_utils::remote_procedure! {
    fn add(a: f64, b: f64) -> f64 {
        a + b
    }
}
```
