#![cfg(windows)]
#![feature(
    maybe_uninit_uninit_array,
    maybe_uninit_slice,
    maybe_uninit_array_assume_init,
    once_cell,
    io_safety,
    linked_list_cursors,
    vec_into_raw_parts
)]
#![warn(
    unsafe_op_in_unsafe_fn,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::todo,
    clippy::manual_assert,
    clippy::must_use_candidate,
    clippy::inconsistent_struct_constructor,
    clippy::wrong_self_convention,
    clippy::new_without_default,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::borrow_as_ptr
)]
#![cfg_attr(feature = "doc-cfg", doc = include_str!("../crate-doc.md"))]
#![cfg_attr(not(feature = "doc-cfg"), allow(missing_docs))]
#![cfg_attr(feature = "doc-cfg", feature(doc_cfg))]

#[cfg(feature = "syringe")]
mod syringe;
#[cfg(feature = "syringe")]
pub use syringe::*;

/// Module containing process abstractions and utilities.
pub mod process;

#[cfg(feature = "rpc")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc")))]
mod remote_procedure;
#[cfg(feature = "rpc")]
pub use remote_procedure::*;

pub(crate) mod utils;

/// Module containing the error enums used in this crate.
pub mod error;
