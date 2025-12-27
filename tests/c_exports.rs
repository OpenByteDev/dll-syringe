#![cfg(feature = "c-exports")]
#![cfg(feature = "syringe")]

#[allow(unused)]
mod common;

use dll_syringe::{c_exports::*, process::Process};
use std::{ffi::CString, os::windows::io::IntoRawHandle};
use winapi::um::processthreadsapi::GetProcessId;

syringe_test! {
    fn test_syringe_for_process(
        process: OwnedProcess,
        _payload_path: &Path,
    ) {
        let pid = process.pid().unwrap().get();
        let c_syringe = syringe_for_suspended_process(pid);
        assert!(!c_syringe.is_null());

        unsafe { syringe_free(c_syringe) };
    }
}

process_test! {
    fn test_syringe_for_suspended_process(
        process: OwnedProcess,
    ) {
        let pid = process.pid().unwrap().get();
        let c_syringe = syringe_for_suspended_process(pid);
        assert!(!c_syringe.is_null());

        unsafe { syringe_free(c_syringe) };
    } suspended
}

syringe_test! {
    fn test_syringe_inject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let pid = process.pid().unwrap().get();
        let c_syringe = syringe_for_suspended_process(pid);
        assert!(!c_syringe.is_null());

        let dll_path = CString::new(payload_path.to_str().unwrap()).unwrap();
        let injected = unsafe { syringe_inject(c_syringe, dll_path.as_ptr()) };
        assert!(injected);

        unsafe { syringe_free(c_syringe) };
    }
}

syringe_test! {
    fn test_csyringe_find_or_inject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let pid = process.pid().unwrap().get();
        let c_syringe = syringe_for_suspended_process(pid);
        assert!(!c_syringe.is_null());

        let dll_path = CString::new(payload_path.to_str().unwrap()).unwrap();
        let c_module = unsafe { syringe_find_or_inject(c_syringe, dll_path.as_ptr()) };
        assert!(!c_module.is_null());

        unsafe {
            syringe_free(c_syringe);
        }
    }
}

syringe_test! {
    fn test_csyringe_eject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let pid = process.pid().unwrap().get();
        let c_syringe = syringe_for_suspended_process(pid);
        assert!(!c_syringe.is_null());

        let dll_path = CString::new(payload_path.to_str().unwrap()).unwrap();
        let c_module = unsafe { syringe_find_or_inject(c_syringe, dll_path.as_ptr()) };
        assert!(!c_module.is_null());

        let ejected = unsafe { syringe_eject(c_syringe, c_module) };
        assert!(ejected);

        unsafe { syringe_free(c_syringe) };
    }
}
