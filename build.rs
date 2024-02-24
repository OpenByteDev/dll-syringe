fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/c_exports.rs")
        .csharp_dll_name("dll_syringe")
        .csharp_class_accessibility("public")
        .csharp_namespace("dll_syringe.Net.Sys")
        .generate_csharp_file("bindings/csharp/NativeMethods.g.cs")
        .unwrap();
}
