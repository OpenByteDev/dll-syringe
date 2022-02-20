mod process;
pub use process::*;

mod owned;
pub use owned::*;

mod borrowed;
pub use borrowed::*;

mod module;
pub use module::*;

#[cfg_attr(not(feature = "process_memory"), allow(dead_code))]
#[cfg(any(feature = "process_memory", feature = "doc_cfg"))]
#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "process_memory")))]
/// Module containing utilities for dealing with memory of another process.
pub mod memory;
#[cfg_attr(not(feature = "process_memory"), allow(dead_code))]
#[cfg(not(any(feature = "process_memory", feature = "doc_cfg")))]
/// Module containing utilities for dealing with memory of another process.
pub(crate) mod memory;
