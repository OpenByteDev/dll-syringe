fn main() {
    #[cfg(feature = "c")]
    build_c();

    #[cfg(feature = "csharp")]
    build_csharp();
}

#[cfg(feature = "c")]
fn build_c() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = cbindgen::Config::from_root_or_default(&crate_dir);
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("bindings/c/dll-syringe.h");
}

#[cfg(feature = "csharp")]
fn build_csharp() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_dll_name("DllSyringe")
        .csharp_class_accessibility("public")
        .csharp_namespace("DllSyringe.Net.Sys")
        .generate_csharp_file("bindings/csharp/NativeMethods.g.cs")
        .unwrap();
}
