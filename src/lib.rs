#![cfg(windows)]
#![feature(
    maybe_uninit_uninit_array,
    maybe_uninit_slice,
    maybe_uninit_array_assume_init,
    once_cell,
    const_generics_defaults
)]
#![warn(unsafe_op_in_unsafe_fn)]

mod syringe;
pub use syringe::*;

mod process;
pub use process::*;

mod process_module;
pub use process_module::*;

mod injected_module;
pub use injected_module::*;

pub(crate) mod utils;

pub mod error;
