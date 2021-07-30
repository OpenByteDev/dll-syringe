use std::time::Duration;

use stopwatch::Stopwatch;

pub(crate) fn retry<R, E>(operation: impl Fn() -> Result<R, E>, timeout: Duration) -> Result<R, E> {
    retry_with_filter(operation, |_| true, timeout)
}

pub(crate) fn retry_with_filter<R, E>(
    operation: impl Fn() -> Result<R, E>,
    predicate: impl Fn(&R) -> bool,
    timeout: Duration,
) -> Result<R, E> {
    retry_with_args_and_filter(|_| operation(), predicate, timeout, &())
}

pub(crate) fn retry_with_args<A, R, E>(
    operation: impl Fn(&A) -> Result<R, E>,
    timeout: Duration,
    args: &A,
) -> Result<R, E> {
    retry_with_args_and_filter(operation, |_| true, timeout, args)
}

pub(crate) fn retry_with_args_and_filter<A, R, E>(
    operation: impl Fn(&A) -> Result<R, E>,
    predicate: impl Fn(&R) -> bool,
    timeout: Duration,
    args: &A,
) -> Result<R, E> {
    let stopwatch = Stopwatch::start_new();
    loop {
        match operation(args) {
            Ok(result) => {
                if predicate(&result) {
                    return Ok(result);
                }
            }
            Err(err) => {
                if stopwatch.elapsed() >= timeout {
                    return Err(err);
                }
            }
        }
    }
}
