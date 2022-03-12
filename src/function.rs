use std::{fmt::Display, str::FromStr};

use winapi::shared::minwindef::{__some_function, FARPROC};

pub type RawFunctionPtr = FARPROC;
pub type RawFunctionPtrTarget = __some_function;

/// Trait representing a function.
pub trait FunctionPtr: Sized + Copy + Sync + 'static {
    /// The argument types as a tuple.
    type Args;

    /// The return type.
    type Output;

    /// The function's arity (number of arguments).
    const ARITY: usize;

    /// Is this function unsafe.
    const UNSAFE: bool;

    /// Is this function unsafe.
    const CALLING_CONVENTION: CallingConvention;

    /// Constructs a `Function` from an untyped function pointer.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it can not check if the argument points to a function
    /// of the correct type.
    unsafe fn from_ptr(ptr: RawFunctionPtr) -> Self;

    /// Returns a untyped function pointer for this function.
    fn as_ptr(&self) -> RawFunctionPtr;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallingConvention {
    Rust,
    C,
    System,
    Win64,
    Sysv64,
    Aapcs,
    Cdecl,
    Stdcall,
    Fastcall,
    Vectorcall,
}

impl CallingConvention {
    #[must_use]
    pub const fn to_str(&self) -> &'static str {
        match self {
            CallingConvention::Rust => "Rust",
            CallingConvention::C => "C",
            CallingConvention::System => "System",
            CallingConvention::Win64 => "Win64",
            CallingConvention::Sysv64 => "Sysv64",
            CallingConvention::Aapcs => "Aapcs",
            CallingConvention::Cdecl => "Cdecl",
            CallingConvention::Stdcall => "Stdcall",
            CallingConvention::Fastcall => "Fastcall",
            CallingConvention::Vectorcall => "Vectorcall",
        }
    }
}

impl FromStr for CallingConvention {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" | "Rust" => Ok(CallingConvention::C),
            "C" => Ok(CallingConvention::C),
            "system" => Ok(CallingConvention::System),
            "win64" => Ok(CallingConvention::Win64),
            "sysv64" => Ok(CallingConvention::Sysv64),
            "aapcs" => Ok(CallingConvention::Aapcs),
            "cdecl" => Ok(CallingConvention::Cdecl),
            "stdcall" => Ok(CallingConvention::Stdcall),
            "fastcall" => Ok(CallingConvention::Fastcall),
            "vectorcall" => Ok(CallingConvention::Vectorcall),
            _ => Err(()),
        }
    }
}

#[must_use]
const fn call_conv_from_str(conv: &'static str) -> Option<CallingConvention> {
    if konst::eq_str(conv, "") || konst::eq_str(conv, "Rust") {
        Some(CallingConvention::Rust)
    } else if konst::eq_str(conv, "C") {
        Some(CallingConvention::C)
    } else if konst::eq_str(conv, "system") {
        Some(CallingConvention::System)
    } else if konst::eq_str(conv, "win64") {
        Some(CallingConvention::Win64)
    } else if konst::eq_str(conv, "sysv64") {
        Some(CallingConvention::Sysv64)
    } else if konst::eq_str(conv, "aapcs") {
        Some(CallingConvention::Aapcs)
    } else if konst::eq_str(conv, "cdecl") {
        Some(CallingConvention::Cdecl)
    } else if konst::eq_str(conv, "stdcall") {
        Some(CallingConvention::Stdcall)
    } else if konst::eq_str(conv, "fastcall") {
        Some(CallingConvention::Fastcall)
    } else if konst::eq_str(conv, "vectorcall") {
        Some(CallingConvention::Vectorcall)
    } else {
        None
    }
}

impl Display for CallingConvention {
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
        impl<Ret: 'static, $($ty: 'static),*> crate::function::FunctionPtr for $fn_type {
            type Args = ($($ty,)*);
            type Output = Ret;

            const ARITY: ::core::primitive::usize = impl_fn!(@count ($($ty)*));
            const UNSAFE: ::core::primitive::bool = $is_unsafe;
            const CALLING_CONVENTION: crate::function::CallingConvention = match call_conv_from_str($call_conv) {
                Some(c) => c,
                None => panic!(concat!("invalid or unknown calling convention: ", $call_conv)),
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
