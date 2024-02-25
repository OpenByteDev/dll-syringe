use crate::process::{BorrowedProcessModule, OwnedProcess};
use crate::Syringe;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::null_mut;

// Note: Don't specify [repr(C)] for these structs, as they are not passed to C code.
// The C code only interacts with pointers to these structs.

/// Represents an instance of a Syringe for a target process.
#[derive(Debug)]
pub struct CSyringe {
    syringe: Syringe,
}

/// Represents a module within a process, allowing for ejection of a previously injected module.
#[derive(Debug)]
pub struct CProcessModule<'a> {
    module: BorrowedProcessModule<'a>,
}

/// Creates a new `Syringe` instance for a process identified by PID.
///
/// # Arguments
///
/// * `pid` - The PID of the target process.
///
/// # Returns
///
/// A pointer to a `CSyringe` instance, or null if the process could not be opened.
#[no_mangle]
pub extern "C" fn syringe_for_process(pid: u32) -> *mut CSyringe {
    let process = match OwnedProcess::from_pid(pid) {
        Ok(process) => process,
        Err(_) => return null_mut(),
    };
    let syringe = Syringe::for_process(process);
    let boxed = Box::new(CSyringe { syringe });
    Box::into_raw(boxed) // Directly return a pointer to the boxed CSyringe
}

/// Creates a new `Syringe` instance for a suspended process identified by PID.
///
/// # Arguments
///
/// * `pid` - The PID of the target suspended process.
///
/// # Returns
///
/// A pointer to a `CSyringe` instance, or null if the process could not be opened or initialized.
#[no_mangle]
pub extern "C" fn syringe_for_suspended_process(pid: u32) -> *mut CSyringe {
    let process = match OwnedProcess::from_pid(pid) {
        Ok(process) => process,
        Err(_) => return null_mut(),
    };

    match Syringe::for_suspended_process(process) {
        Ok(syringe) => {
            let boxed = Box::new(CSyringe { syringe });
            Box::into_raw(boxed) // Return a pointer to the boxed CSyringe
        }
        Err(_) => null_mut(),
    }
}

/// Injects a DLL into the target process associated with the given `Syringe`.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
///
/// # Arguments
///
/// * `c_syringe` - A pointer to the `CSyringe` instance.
/// * `dll_path` - A C string path to the DLL to be injected.
///
/// # Returns
///
/// `true` if injection succeeded, otherwise `false`.
#[no_mangle]
pub unsafe extern "C" fn syringe_inject(c_syringe: *mut CSyringe, dll_path: *const c_char) -> bool {
    let c_syringe = unsafe { &mut *c_syringe };
    let path_str = unsafe { CStr::from_ptr(dll_path).to_str().unwrap() };
    c_syringe.syringe.inject(Path::new(path_str)).is_ok()
}

/// Finds or injects a DLL into the target process.
///
/// If the DLL is already present in the target process, it returns the existing module.
/// Otherwise, it injects the DLL.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
///
/// # Arguments
///
/// * `c_syringe` - A pointer to the `CSyringe` instance.
/// * `dll_path` - A C string path to the DLL to be injected.
///
/// # Returns
///
/// A pointer to a `CProcessModule`, or null if the operation failed.
#[no_mangle]
pub unsafe extern "C" fn syringe_find_or_inject<'a>(
    c_syringe: *mut CSyringe,
    dll_path: *const c_char,
) -> *mut CProcessModule<'a> {
    let syringe = unsafe { &mut (*c_syringe).syringe };
    let path_str = unsafe { CStr::from_ptr(dll_path).to_str().unwrap() };
    match syringe.find_or_inject(Path::new(path_str)) {
        Ok(module) => {
            let c_module = Box::new(CProcessModule { module });
            Box::into_raw(c_module)
        }
        Err(_) => null_mut(),
    }
}

/// Ejects a module from the target process.
///
/// # Arguments
///
/// * `c_syringe` - A pointer to the `CSyringe` instance.
/// * `c_module` - A pointer to the `CProcessModule` to be ejected.
///
/// # Returns
///
/// `true` if ejection succeeded, otherwise `false`.
///
/// # Safety
/// This is safe as long as it has a valid pointer to a Syringe and Module.
#[no_mangle]
pub unsafe extern "C" fn syringe_eject(
    c_syringe: *mut CSyringe,
    c_module: *mut CProcessModule<'_>,
) -> bool {
    let syringe = unsafe { &mut (*c_syringe).syringe };
    let module = unsafe { &mut (*c_module).module };
    syringe.eject(*module).is_ok()
}

/// Frees a `CSyringe` instance.
///
/// # Arguments
///
/// * `c_syringe` - A pointer to the `CSyringe` instance to be freed.
///
/// # Safety
/// This is safe as long as it has a valid pointer to a Syringe instance.
#[no_mangle]
pub unsafe extern "C" fn syringe_free(c_syringe: *mut CSyringe) {
    if !c_syringe.is_null() {
        unsafe {
            let _ = Box::from_raw(c_syringe); // drop
        }
    }
}

/// Frees a `CProcessModule` instance.
///
/// # Arguments
///
/// * `c_module` - A pointer to the `CProcessModule` to be freed.
///
/// # Safety
/// This is safe as long as it has a valid pointer to a module
/// created by this Syringe instance.
#[no_mangle]
pub unsafe extern "C" fn syringe_module_free(c_module: *mut CProcessModule<'_>) {
    if !c_module.is_null() {
        unsafe {
            let _ = Box::from_raw(c_module); // drop
        }
    }
}
