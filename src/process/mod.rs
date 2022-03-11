mod process;
pub use process::*;

mod owned;
pub use owned::*;

mod borrowed;
pub use borrowed::*;

mod module;
pub use module::*;

#[cfg_attr(not(feature = "process-memory"), allow(dead_code))]
#[cfg(feature = "process-memory")]
#[cfg_attr(feature = "doc-cfg", doc(cfg(feature = "process-memory")))]
/// Module containing utilities for dealing with memory of another process.
pub mod memory;
#[cfg_attr(not(feature = "process-memory"), allow(dead_code))]
#[cfg(not(feature = "process-memory"))]
/// Module containing utilities for dealing with memory of another process.
pub(crate) mod memory;
