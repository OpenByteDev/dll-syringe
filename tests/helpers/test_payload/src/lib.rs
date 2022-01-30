use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

#[no_mangle]
extern "system" fn DllMain(
    _hinst_dll: HINSTANCE, // handle to DLL module
    _fdw_reason: DWORD, // reason for calling function
    _lp_reserved: LPVOID) -> BOOL {
    1
}

#[no_mangle]
extern "system" fn echo(arg: LPVOID) -> DWORD {
    arg as DWORD
}

#[no_mangle]
extern "system" fn add(numbers: *const (f64, f64), result: *mut f64) {
    unsafe { *result = (*numbers).0 + (*numbers).1 }
}

#[no_mangle]
pub extern "system" fn echo2(i: *const u32, o: *mut u32) -> u32 {
    unsafe { *o = *i };
    0
}
