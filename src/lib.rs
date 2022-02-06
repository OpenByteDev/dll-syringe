#![cfg(windows)]
#![feature(
    maybe_uninit_uninit_array,
    maybe_uninit_slice,
    maybe_uninit_array_assume_init,
    once_cell,
    io_safety,
    linked_list_cursors
)]
#![warn(
    unsafe_op_in_unsafe_fn,
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    clippy::todo,
    clippy::manual_assert,
    clippy::must_use_candidate,
    clippy::inconsistent_struct_constructor,
    clippy::wrong_self_convention
)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::borrow_as_ptr
)]
#![doc = include_str!("../crate-doc.md")]

mod syringe;
pub use syringe::*;

#[cfg(feature = "remote_procedure")]
mod remote_procedure;
#[cfg(feature = "remote_procedure")]
pub use remote_procedure::*;

mod process;
pub use process::*;

pub(crate) mod utils;

/// Module containing the error enums used in this crate.
pub mod error;
