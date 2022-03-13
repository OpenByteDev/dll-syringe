use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

#[no_mangle]
extern "system" fn DllMain(
    _hinst_dll: HINSTANCE, // handle to DLL module
    _fdw_reason: DWORD, // reason for calling function
    _lp_reserved: LPVOID) -> BOOL {
    1
}

#[no_mangle]
pub extern "system" fn echo(i: *const u32, o: *mut u32) {
    unsafe { *o = *i };
}

#[no_mangle]
pub extern "system" fn add(numbers: *const (f64, f64), result: *mut f64) {
    unsafe { *result = (*numbers).0 + (*numbers).1 }
}

dll_syringe::payload_procedure! {
    fn add3(a: u32, b: u32) -> u32 {
        a + b
    }
}

dll_syringe::payload_procedure! {
    fn sum(nums: Vec<u64>) -> u64 {
        nums.iter().sum()
    }
}

dll_syringe::payload_procedure! {
    fn does_panic() {
        panic!("Some error message")
    }
}
