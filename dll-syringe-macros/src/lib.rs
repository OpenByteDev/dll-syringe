use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_attribute]
pub fn payload_procedure(_: TokenStream, input: TokenStream) -> TokenStream {
    let item = syn::parse_macro_input!(input as syn::ItemFn);
    let fn_ident = item.sig.ident;
    let fn_args = item.sig.inputs;

    let mut rpc_args = quote! {}; // (a, b)
    let mut inner_args = quote! {}; // (a: type, b: type)
    for arg in fn_args {
        if let syn::FnArg::Typed(pat_type) = arg {
            let pat = pat_type.pat.clone();
            rpc_args = quote! { #rpc_args #pat, };
            inner_args = quote! { #inner_args #pat_type, };
        }
    }

    let ret_value = match item.sig.output {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ref ty) => quote! { #ty },
    };

    let fn_contents = item.block;

    quote! {
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn #fn_ident(__args_and_params: *mut ::core::ffi::c_void) {
            ::dll_syringe::payload_utils::__payload_procedure_helper(__args_and_params, |__args| {
                let (#rpc_args) = __args;
                fn __inner(#inner_args) -> #ret_value {
                    #fn_contents
                }
                __inner(#rpc_args)
            });
        }
    }
    .into()
}
