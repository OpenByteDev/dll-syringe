fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/c_api.rs")
        .csharp_dll_name("DllSyringe")
        .csharp_class_accessibility("public")
        .csharp_namespace("DllSyringe.Net.Sys")
        .generate_csharp_file("bindings/csharp/NativeMethods.g.cs")
        .unwrap();
}
