mod process;
pub use process::*;

mod process_ref;
pub use process_ref::*;

mod process_module;
pub use process_module::*;

/// A handle to a process.
/// Equivalent to [`HANDLE`](std::os::windows::raw::HANDLE).
pub type ProcessHandle = std::os::windows::raw::HANDLE;
