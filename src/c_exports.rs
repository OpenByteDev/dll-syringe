use crate::{
    process::{BorrowedProcessModule, ModuleHandle, OwnedProcess},
    Syringe,
};
use std::{ffi::CStr, os::raw::c_char, path::Path, ptr};

/// Creates a new `Syringe` instance for a process identified by PID.
///
/// # Arguments
/// * `pid` - The PID of the target process.
///
/// # Returns
/// A pointer to a `Syringe` instance, or null if the process could not be opened.
///
/// # Note
/// The returned instance has to freed using `syringe_free`.
#[no_mangle]
pub extern "C" fn syringe_for_process(pid: u32) -> *mut Syringe {
    let Ok(process) = OwnedProcess::from_pid(pid) else {
        return ptr::null_mut();
    };

    let syringe = Syringe::for_process(process);
    let boxed = Box::new(syringe);
    Box::into_raw(boxed)
}

/// Creates a new `Syringe` instance for a suspended process identified by PID.
///
/// # Arguments
/// * `pid` - The PID of the target suspended process.
///
/// # Returns
/// A pointer to a `Syringe` instance, or null if the process could not be opened or initialized.
///
/// # Note
/// The returned instance has to freed using `syringe_free`.
#[no_mangle]
pub extern "C" fn syringe_for_suspended_process(pid: u32) -> *mut Syringe {
    let Ok(process) = OwnedProcess::from_pid(pid) else {
        return ptr::null_mut();
    };

    match Syringe::for_suspended_process(process) {
        Ok(syringe) => {
            let boxed = Box::new(syringe);
            Box::into_raw(boxed)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Injects a DLL into the target process associated with the given `Syringe`.
///
/// # Arguments
/// * `syringe` - A pointer to the `Syringe` instance.
/// * `dll_path` - A C string path to the DLL to be injected.
///
/// # Returns
/// `true` if injection succeeded, otherwise `false`.
///
/// # Safety
/// The caller must ensure the given syringe pointer is valid.
#[no_mangle]
pub unsafe extern "C" fn syringe_inject(syringe: *mut Syringe, dll_path: *const c_char) -> bool {
    let syringe = unsafe { &mut *syringe };
    let Ok(path_str) = unsafe { CStr::from_ptr(dll_path) }.to_str() else {
        return false;
    };
    syringe.inject(Path::new(path_str)).is_ok()
}

/// Finds or injects a DLL into the target process.
///
/// If the DLL is already present in the target process, it returns the existing module.
/// Otherwise, it injects the DLL.
///
/// # Arguments
/// * `syringe` - A pointer to the `Syringe` instance.
/// * `dll_path` - A C string path to the DLL to be injected.
///
/// # Returns
/// The base address of the loaded DLL or `null` if the operation failed.
///
/// # Safety
/// The caller must ensure that the given syringe pointer is valid.
#[no_mangle]
pub unsafe extern "C" fn syringe_find_or_inject(
    syringe: *mut Syringe,
    dll_path: *const c_char,
) -> ModuleHandle {
    let syringe = unsafe { &mut *syringe };
    let Ok(path_str) = unsafe { CStr::from_ptr(dll_path) }.to_str() else {
        return ptr::null_mut();
    };
    match syringe.find_or_inject(Path::new(path_str)) {
        Ok(module) => module.handle(),
        Err(_) => ptr::null_mut(),
    }
}

/// Ejects a module from the target process.
///
/// # Arguments
/// * `syringe` - A pointer to the `Syringe` instance.
/// * `module` - The base address of the module to be ejected.
///
/// # Returns
/// `true` if ejection succeeded, otherwise `false`.
///
/// # Safety
/// The caller must ensure that the given syringe pointer is valid and
/// the handle belongs to a module in the process of the syringe.
#[no_mangle]
pub unsafe extern "C" fn syringe_eject(syringe: *mut Syringe, module: ModuleHandle) -> bool {
    let syringe = unsafe { &mut *syringe };
    let module = unsafe { BorrowedProcessModule::new_unchecked(module, syringe.process()) };
    syringe.eject(module).is_ok()
}

/// Frees a `Syringe` instance.
///
/// # Arguments
/// * `syringe` - A pointer to the `Syringe` instance to be freed.
///
/// # Safety
/// The caller must ensure that the given syringe pointer is valid or null.
#[no_mangle]
pub unsafe extern "C" fn syringe_free(syringe: *mut Syringe) {
    if !syringe.is_null() {
        unsafe {
            drop(Box::from_raw(syringe));
        }
    }
}
