use dll_syringe::process::{BorrowedProcess, OwnedProcess, Process};
use std::{mem, fs, time::Duration};

#[allow(unused)]
mod common;

process_test! {
    fn list_modules_on_running_succeeds(
        process: OwnedProcess
    ) {
        process.modules().unwrap();
    }
}

process_test! {
    fn list_module_handles_on_running_succeeds(
        process: OwnedProcess
    ) {
        let _ = process.borrowed().module_handles().unwrap().for_each(mem::drop);
    }
}

process_test! {
    fn wait_for_module_with_kernel32_succeeds(
        process: OwnedProcess
    ) {
        process.wait_for_module_by_name("kernel32.dll", Duration::from_secs(1)).unwrap();
    }
}

process_test! {
    fn list_module_handles_on_crashed_does_not_hang(
        process: OwnedProcess
    ) {
        process.kill().unwrap();
        // assert this does not hang
        let _ = process.borrowed().module_handles();
    }
}

process_test! {
    fn is_alive_is_true_for_running(
        process: OwnedProcess
    ) {
        assert!(process.is_alive());
        process.kill().unwrap();
        assert!(!process.is_alive());
    }
}

process_test! {
    fn is_alive_is_false_for_killed(
        process: OwnedProcess
    ) {
        process.kill().unwrap();
        assert!(!process.is_alive());
    }
}

process_test! {
    fn path_returns_correct_path(
        process: OwnedProcess
    ) {
        let path = process.path().unwrap();
        assert_eq!(path.components().last().unwrap().as_os_str().to_string_lossy().as_ref(), "test_target.exe");
        assert!(path.exists());
    }
}

process_test! {
    fn base_name_returns_correct_path(
        process: OwnedProcess
    ) {
        let name = process.base_name().unwrap().to_string_lossy().to_string();
        assert_eq!("test_target.exe", name);
    }
}

process_test! {
    fn kill_guard_kills_process_on_drop(
        process: OwnedProcess
    ) {
        let guard = process.try_clone().unwrap().kill_on_drop();
        assert!(guard.is_alive());
        drop(guard);
        assert!(!process.is_alive());
    }
}

process_test! {
    fn long_process_paths_are_supported(
        process: OwnedProcess
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

        let process_with_long_name: OwnedProcess = Command::new(&exe_path)
            .spawn()
            .unwrap()
            .into();
        assert_eq!(process_with_long_name.path().unwrap().canonicalize().unwrap(), exe_path.canonicalize().unwrap());
    }
}

#[test]
fn current_process_is_current() {
    let process = BorrowedProcess::current();
    assert!(process.is_current());

    let process = OwnedProcess::from_pid(process.pid().unwrap().get()).unwrap();
    assert!(process.is_current());
}

#[test]
fn remote_process_is_not_current() {
    let mut all = OwnedProcess::all().into_iter();
    let process_a = all.next().unwrap();
    let process_b = all.next().unwrap();
    assert!(!process_a.is_current() || !process_b.is_current());
}

#[test]
fn current_pseudo_process_eq_current_process() {
    let pseudo = BorrowedProcess::current();
    let normal = OwnedProcess::from_pid(pseudo.pid().unwrap().get()).unwrap();

    assert_eq!(pseudo, normal.borrowed());
    assert_eq!(pseudo, normal);
    assert_eq!(pseudo.try_to_owned().unwrap(), normal);
    assert_eq!(pseudo, normal.try_clone().unwrap());
}
