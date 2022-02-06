mod process;
pub use process::*;

mod process_ref;
pub use process_ref::*;

mod process_module;
pub use process_module::*;

#[cfg_attr(not(feature = "process_memory"), allow(dead_code))]
mod process_memory;
#[cfg(feature = "process_memory")]
pub use process_memory::*;
#[cfg(not(feature = "process_memory"))]
pub(crate) use process_memory::*;

#[allow(dead_code)]
mod raw_allocator;
pub(crate) use raw_allocator::*;

#[allow(dead_code)]
mod remote_box;
pub(crate) use remote_box::*;

/// A handle to a process.
/// Equivalent to [`HANDLE`](std::os::windows::raw::HANDLE).
pub type ProcessHandle = std::os::windows::raw::HANDLE;
