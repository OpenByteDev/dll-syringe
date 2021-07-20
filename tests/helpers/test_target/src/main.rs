fn main() {
    // this loop keeps the process alive for a while, so that the tests can run.
    // we dont want to wait indefinitely to avoid creating sleeping zombies.
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
