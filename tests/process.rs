#[allow(unused)]
mod common;

process_test! {
    fn list_modules(
        process: Process
    ) {
        process.modules().unwrap();
    }
}

process_test! {
    fn list_module_handles(
        process: Process
    ) {
        process.module_handles().unwrap();
    }
}

process_test! {
    fn list_module_handles_on_crashed(
        process: Process
    ) {
        process.clone().kill().unwrap();
        // assert this does not hang
        let _ = process.module_handles();
    }
}

process_test! {
    fn is_alive(
        process: Process
    ) {
        assert!(process.is_alive());
        process.clone().kill().unwrap();
        assert!(!process.is_alive());
    }
}

process_test! {
    fn path(
        process: Process
    ) {
        let path = process.path().unwrap().to_string_lossy().to_string();
        assert!(path.ends_with("test_target.exe"));
    }
}

process_test! {
    fn base_name(
        process: Process
    ) {
        let name = process.base_name().unwrap().to_string_lossy().to_string();
        assert_eq!("test_target.exe", name);
    }
}

process_test! {
    fn kill_guard(
        process: Process
    ) {
        let guard = process.try_clone().unwrap().kill_on_drop();
        assert!(guard.is_alive());
        drop(guard);
        assert!(!process.is_alive());
    }
}
