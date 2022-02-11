use dll_syringe::Syringe;

#[allow(unused)]
mod common;

syringe_test! {
    fn eject(
        process: Process,
        payload_path: &Path,
    ) {
        let mut syringe = Syringe::for_process(&process);
        let module = syringe.inject(payload_path).unwrap();
        syringe.eject(module).unwrap();
    }
}
