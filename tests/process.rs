use dll_syringe::{Process, ProcessRef};
use std::{fs, time::Duration};

#[allow(unused)]
mod common;

process_test! {
    fn list_modules_on_running_succeeds(
        process: Process
    ) {
        process.modules().unwrap();
    }
}

process_test! {
    fn list_module_handles_on_running_succeeds(
        process: Process
    ) {
        process.module_handles().unwrap();
    }
}

process_test! {
    fn wait_for_module_with_kernel32_suceeds(
        process: Process
    ) {
        process.wait_for_module_by_name("kernel32.dll", Duration::from_secs(1)).unwrap();
    }
}

process_test! {
    fn list_module_handles_on_crashed_does_not_hang(
        process: Process
    ) {
        process.kill().unwrap();
        // assert this does not hang
        let _ = process.module_handles();
    }
}

process_test! {
    fn is_alive_is_true_for_running(
        process: Process
    ) {
        assert!(process.is_alive());
        process.kill().unwrap();
        assert!(!process.is_alive());
    }
}

process_test! {
    fn is_alive_is_false_for_killed(
        process: Process
    ) {
        process.kill().unwrap();
        assert!(!process.is_alive());
    }
}

process_test! {
    fn path_returns_correct_path(
        process: Process
    ) {
        let path = process.path().unwrap();
        assert_eq!(path.components().last().unwrap().as_os_str().to_string_lossy().as_ref(), "test_target.exe");
        assert!(path.exists());
    }
}

process_test! {
    fn base_name_returns_correct_path(
        process: Process
    ) {
        let name = process.base_name().unwrap().to_string_lossy().to_string();
        assert_eq!("test_target.exe", name);
    }
}

process_test! {
    fn kill_guard_kills_process_on_drop(
        process: Process
    ) {
        let guard = process.try_clone().unwrap().kill_on_drop();
        assert!(guard.is_alive());
        drop(guard);
        assert!(!process.is_alive());
    }
}

process_test! {
    fn long_process_paths_are_supported(
        process: Process
    ) {
        let process_path = process.path().unwrap();
        process.kill().unwrap();

        let base_dir = tempfile::tempdir().unwrap();
        let mut exe_path = base_dir.path().canonicalize().unwrap();
        while exe_path.to_string_lossy().len() < 500 {
            exe_path.push("dir");
        }
        fs::create_dir_all(&exe_path).unwrap();
        exe_path.push("test_target.exe");
        fs::copy(process_path, &exe_path).unwrap();

        let process_with_long_name: Process = Command::new(&exe_path)
            .spawn()
            .unwrap()
            .into();
        assert_eq!(process_with_long_name.path().unwrap().canonicalize().unwrap(), exe_path.canonicalize().unwrap());
    }
}

#[test]
fn current_process_is_current() {
    let process = ProcessRef::current();
    assert!(process.is_current());

    let process = Process::from_pid(process.pid().unwrap().get()).unwrap();
    assert!(process.is_current());
}

#[test]
fn remote_process_is_not_current() {
    let mut all = Process::all().into_iter();
    let process_a = all.next().unwrap();
    let process_b = all.next().unwrap();
    assert!(!process_a.is_current() || !process_b.is_current());
}

#[test]
fn current_pseudo_process_eq_current_process() {
    let pseudo = ProcessRef::current();
    let normal = Process::from_pid(pseudo.pid().unwrap().get()).unwrap();

    assert_eq!(pseudo, normal.get_ref());
    assert_eq!(pseudo, normal);
    assert_eq!(ProcessRef::promote_to_owned(&pseudo).unwrap(), normal);
    assert_eq!(pseudo, ProcessRef::promote_to_owned(&normal).unwrap());
}
