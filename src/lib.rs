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
    clippy::missing_const_for_fn,
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
#![cfg_attr(feature = "doc_cfg", doc = include_str!("../crate-doc.md"))]
#![cfg_attr(not(feature = "doc_cfg"), allow(missing_docs))]
#![cfg_attr(feature = "doc_cfg", feature(doc_cfg))]

mod syringe;
pub use syringe::*;

/// Module containing process abstractions and utilities.
pub mod process;

#[cfg(any(feature = "remote_procedure", feature = "doc_cfg"))]
#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "remote_procedure")))]
mod remote_procedure;
#[cfg(any(feature = "remote_procedure", feature = "doc_cfg"))]
pub use remote_procedure::*;

pub(crate) mod utils;

/// Module containing the error enums used in this crate.
pub mod error;
