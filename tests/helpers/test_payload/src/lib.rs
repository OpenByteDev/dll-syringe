use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

#[no_mangle]
extern "system" fn DllMain(
    _hinst_dll: HINSTANCE, // handle to DLL module
    _fdw_reason: DWORD,    // reason for calling function
    _lp_reserved: LPVOID,
) -> BOOL {
    1
}

dll_syringe::payload_procedure! {
    fn add(a: u32, b: u32) -> u32 {
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

#[no_mangle]
pub extern "system" fn add_raw(a: u32, b: u32) -> u32 {
    a + b
}

#[no_mangle]
pub extern "C" fn add_raw_c(a: u32, b: u32) -> u32 {
    a + b
}

#[no_mangle]
pub extern "system" fn sub_raw(a: u32, b: u32) -> u32 {
    a - b
}

#[no_mangle]
pub extern "system" fn add_smol_raw(a: u16, b: u8) -> u16 {
    a + b as u16
}

#[no_mangle]
pub extern "system" fn sum_5_raw(a1: u32, a2: u32, a3: u32, a4: u32, a5: u32) -> u32 {
    a1 + a2 + a3 + a4 + a5
}

#[no_mangle]
pub extern "system" fn sum_10_raw(
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    a5: u32,
    a6: u32,
    a7: u32,
    a8: u32,
    a9: u32,
    a10: u32,
) -> u32 {
    a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10
}

#[no_mangle]
pub extern "system" fn sub_float_raw(a: f32, b: f32) -> f32 {
    a - b
}

#[no_mangle]
pub extern "C" fn sub_float_raw_c(a: f32, b: f32) -> f32 {
    a - b
}

#[no_mangle]
pub extern "C" fn sum_10_raw_c(
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    a5: u32,
    a6: u32,
    a7: u32,
    a8: u32,
    a9: u32,
    a10: u32,
) -> u32 {
    a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10
}

#[no_mangle]
pub extern "C" fn crash() {
    let ptr = std::ptr::null_mut::<u32>();
    std::hint::black_box(unsafe { *std::hint::black_box(ptr) });
}
