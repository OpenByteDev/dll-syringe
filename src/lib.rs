#![cfg(windows)]
#![feature(
    maybe_uninit_uninit_array,
    maybe_uninit_slice,
    maybe_uninit_array_assume_init,
    once_cell,
    io_safety,
    linked_list_cursors
)]
#![allow(clippy::module_inception)]
#![warn(unsafe_op_in_unsafe_fn, missing_docs)]
#![cfg_attr(
    any(
        not(target_arch = "x86_64"),
        not(feature = "into_x86_from_x64"),
        not(feature = "call_remote_procedure")
    ),
    allow(unused_imports)
)]
#![doc = include_str!("../crate-doc.md")]

mod syringe;
pub use syringe::*;

mod process;
pub use process::*;

pub(crate) mod utils;

/// Module containing the error enums used in this crate.
pub mod error;
