use std::{fmt::Display, str::FromStr};

use winapi::shared::minwindef::{__some_function, FARPROC};

/// Type alias for a raw untyped function pointer.
pub type RawFunctionPtr = FARPROC;
/// Type alias for the pointee of a raw function pointer.
pub type RawFunctionPtrTarget = __some_function;

/// Trait representing a function.
///
/// # Safety
/// This trait should only be implemented for function pointers and the associated types and constants have to match the function pointer type.
pub unsafe trait FunctionPtr: Sized + Copy + Send + Sync + 'static {
    /// The argument types as a tuple.
    type Args;

    /// The argument types as a tuple of references.
    type RefArgs<'a>;

    /// The return type.
    type Output;

    /// The function's arity (number of arguments).
    const ARITY: usize;

    /// Is this function unsafe.
    const UNSAFE: bool;

    /// The ABI of this function.
    const ABI: Abi;

    /// Constructs a [`FunctionPtr`] from an untyped function pointer.
    ///
    /// # Safety
    /// This function is unsafe because it can not check if the argument points to a function
    /// of the correct type.
    unsafe fn from_ptr(ptr: RawFunctionPtr) -> Self;

    /// Returns a untyped function pointer for this function.
    fn as_ptr(&self) -> RawFunctionPtr;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// The abi or calling convention of a function pointer.
pub enum Abi {
    /// The default ABI when you write a normal `fn foo()` in any Rust code.
    Rust,
    /// This is the same as `extern fn foo()`; whatever the default your C compiler supports.
    C,
    /// Usually the same as [`extern "C"`](Abi::C), except on Win32, in which case it's [`"stdcall"`](Abi::Stdcall), or what you should use to link to the Windows API itself.
    System,
    /// The default for C code on x86_64 Windows.
    Win64,
    /// The default for C code on non-Windows x86_64.
    Sysv64,
    /// The default for ARM.
    Aapcs,
    /// The default for x86_32 C code.
    Cdecl,
    /// The default for the Win32 API on x86_32.
    Stdcall,
    /// The `fastcall` ABI -- corresponds to MSVC's `__fastcall` and GCC and clang's `__attribute__((fastcall))`
    Fastcall,
    /// The `vectorcall` ABI -- corresponds to MSVC's `__vectorcall` and GCC and clang's `__attribute__((vectorcall))`
    Vectorcall,
}

impl Abi {
    /// Returns the string representation of this ABI.
    #[must_use]
    pub const fn to_str(&self) -> &'static str {
        match self {
            Abi::Rust => "Rust",
            Abi::C => "C",
            Abi::System => "System",
            Abi::Win64 => "Win64",
            Abi::Sysv64 => "Sysv64",
            Abi::Aapcs => "Aapcs",
            Abi::Cdecl => "Cdecl",
            Abi::Stdcall => "Stdcall",
            Abi::Fastcall => "Fastcall",
            Abi::Vectorcall => "Vectorcall",
        }
    }
}

impl FromStr for Abi {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" | "Rust" => Ok(Abi::C),
            "C" => Ok(Abi::C),
            "system" => Ok(Abi::System),
            "win64" => Ok(Abi::Win64),
            "sysv64" => Ok(Abi::Sysv64),
            "aapcs" => Ok(Abi::Aapcs),
            "cdecl" => Ok(Abi::Cdecl),
            "stdcall" => Ok(Abi::Stdcall),
            "fastcall" => Ok(Abi::Fastcall),
            "vectorcall" => Ok(Abi::Vectorcall),
            _ => Err(()),
        }
    }
}

#[must_use]
const fn call_conv_from_str(conv: &'static str) -> Option<Abi> {
    if konst::eq_str(conv, "") || konst::eq_str(conv, "Rust") {
        Some(Abi::Rust)
    } else if konst::eq_str(conv, "C") {
        Some(Abi::C)
    } else if konst::eq_str(conv, "system") {
        Some(Abi::System)
    } else if konst::eq_str(conv, "win64") {
        Some(Abi::Win64)
    } else if konst::eq_str(conv, "sysv64") {
        Some(Abi::Sysv64)
    } else if konst::eq_str(conv, "aapcs") {
        Some(Abi::Aapcs)
    } else if konst::eq_str(conv, "cdecl") {
        Some(Abi::Cdecl)
    } else if konst::eq_str(conv, "stdcall") {
        Some(Abi::Stdcall)
    } else if konst::eq_str(conv, "fastcall") {
        Some(Abi::Fastcall)
    } else if konst::eq_str(conv, "vectorcall") {
        Some(Abi::Vectorcall)
    } else {
        None
    }
}

impl Display for Abi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

macro_rules! impl_fn {
    (@recurse () ($($nm:ident : $ty:ident),*)) => {
        impl_fn!(@impl_all ($($nm : $ty),*));
    };
    (@recurse ($hd_nm:ident : $hd_ty:ident $(, $tl_nm:ident : $tl_ty:ident)*) ($($nm:ident : $ty:ident),*)) => {
        impl_fn!(@impl_all ($($nm : $ty),*));
        impl_fn!(@recurse ($($tl_nm : $tl_ty),*) ($($nm : $ty,)* $hd_nm : $hd_ty));
    };

    (@impl_all ($($nm:ident : $ty:ident),*)) => {
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("Rust")     fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("cdecl")    fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("stdcall")  fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("fastcall") fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("win64")    fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("sysv64")   fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("aapcs")    fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("C")        fn($($ty),*) -> Ret);
        impl_fn!(@impl_u_and_s ($($nm : $ty),*) ("system")   fn($($ty),*) -> Ret);
    };

    (@impl_u_and_s ($($nm:ident : $ty:ident),*) ($call_conv:expr) fn($($param_ty:ident),*) -> $ret:ty) => {
        impl_fn!(@impl_core ($($nm : $ty),*) (extern $call_conv fn($($param_ty),*) -> $ret) (false) ($call_conv));
        impl_fn!(@impl_core ($($nm : $ty),*) (unsafe extern $call_conv fn($($param_ty),*) -> $ret) (true) ($call_conv));
    };

    (@impl_core ($($nm:ident : $ty:ident),*) ($fn_type:ty) ($is_unsafe:expr) ($call_conv:expr)) => {
        unsafe impl<Ret: 'static, $($ty: 'static),*> crate::function::FunctionPtr for $fn_type {
            type Args = ($($ty,)*);
            type RefArgs<'a> = ($(&'a $ty,)*);
            type Output = Ret;

            const ARITY: ::core::primitive::usize = impl_fn!(@count ($($ty)*));
            const UNSAFE: ::core::primitive::bool = $is_unsafe;
            const ABI: crate::function::Abi = match call_conv_from_str($call_conv) {
                Some(c) => c,
                None => panic!(concat!("invalid or unknown abi: ", $call_conv)),
            };

            unsafe fn from_ptr(ptr: crate::function::RawFunctionPtr) -> Self {
                ::core::assert!(!ptr.is_null());
                unsafe { ::core::mem::transmute(ptr) }
            }

            fn as_ptr(&self) -> crate::function::RawFunctionPtr {
                *self as crate::function::RawFunctionPtr
            }
        }
    };

    (@count ()) => {
        0
    };
    (@count ($hd:tt $($tl:tt)*)) => {
        1 + impl_fn!(@count ($($tl)*))
    };

    ($($nm:ident : $ty:ident),*) => {
        impl_fn!(@recurse ($($nm : $ty),*) ());
    };
}

impl_fn! {
    __arg_0:  A, __arg_1:  B, __arg_2:  C, __arg_3:  D, __arg_4:  E, __arg_5:  F, __arg_6:  G,
    __arg_7:  H, __arg_8:  I, __arg_9:  J, __arg_10: K, __arg_11: L
}
