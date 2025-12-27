#![cfg(windows)]
#![feature(linked_list_cursors)]
#![cfg_attr(feature = "syringe", feature(once_cell_try))]
#![cfg_attr(feature = "rpc-core", feature(min_specialization))]
#![warn(
    clippy::pedantic,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![allow(
    clippy::module_inception,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::missing_transmute_annotations,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_value,
    clippy::wildcard_imports,
    clippy::redundant_closure_for_method_calls
)]
#![cfg_attr(feature = "doc-cfg", allow(clippy::doc_markdown))]
#![cfg_attr(feature = "doc-cfg", doc = include_str!("../crate-doc.md"))]
#![cfg_attr(not(feature = "doc-cfg"), allow(missing_docs))]
#![cfg_attr(feature = "doc-cfg", feature(doc_cfg))]

#[cfg(feature = "syringe")]
mod syringe;
#[cfg(feature = "syringe")]
pub use syringe::*;

/// Module containing process abstractions and utilities.
pub mod process;

#[cfg(feature = "rpc-core")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "rpc-core")))]
/// Module containing traits and structs regarding remote procedures.
pub mod rpc;

pub(crate) mod utils;

/// Module containing the error enums used in this crate.
pub mod error;
#[cfg(feature = "payload-utils")]
#[doc(hidden)]
pub mod payload_utils;

#[cfg(any(feature = "payload-utils", feature = "rpc-payload"))]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct ArgAndResultBufInfo {
    pub data: u64,
    pub len: u64,
    pub is_error: bool,
}
