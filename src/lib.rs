#![cfg(windows)]
#![feature(maybe_uninit_uninit_array, once_cell)]
#[warn(unsafe_op_in_unsafe_fn)]
mod syringe;
pub use syringe::*;

mod process;
pub use process::*;

mod process_module;
pub use process_module::*;

mod array_or_vec;
pub(crate) use array_or_vec::*;

mod injected_module;
pub use injected_module::*;

mod foreign_process_memory;
pub(crate) use foreign_process_memory::*;

mod retry;
pub(crate) use retry::*;

// TODO: proper error handling
