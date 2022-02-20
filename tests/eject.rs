use dll_syringe::Syringe;

#[allow(unused)]
mod common;

syringe_test! {
    fn eject(
        process: OwnedProcess,
        payload_path: &Path,
    ) {
        let syringe = Syringe::for_process(process);
        let module = syringe.inject(payload_path).unwrap();
        syringe.eject(module).unwrap();
    }
}
