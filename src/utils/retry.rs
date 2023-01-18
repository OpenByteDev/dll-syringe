use std::time::Duration;

use stopwatch2::Stopwatch;

pub(crate) fn retry_with_timeout<R>(
    operation: impl Fn() -> Option<R>,
    timeout: Duration,
) -> Option<R> {
    retry_faillable_until_some_with_timeout(|| Ok::<_, ()>(operation()), timeout).unwrap()
}

pub(crate) fn retry_faillable_with_timeout<R, E>(
    operation: impl Fn() -> Result<R, E>,
    timeout: Duration,
) -> Result<R, E> {
    retry_faillable_until_some_with_timeout(|| operation().map(Some), timeout).map(|o| o.unwrap())
}

pub(crate) fn retry_faillable_until_some_with_timeout<R, E>(
    operation: impl Fn() -> Result<Option<R>, E>,
    timeout: Duration,
) -> Result<Option<R>, E> {
    let mut stopwatch = Stopwatch::default();
    stopwatch.start();
    loop {
        match operation() {
            Ok(result) => {
                if result.is_some() || stopwatch.elapsed() >= timeout {
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

#[cfg(test)]
mod tests {
    use std::{cell::Cell, time::Duration};

    use retry::{retry_faillable_until_some_with_timeout, retry_faillable_with_timeout};

    use crate::utils::retry;

    #[test]
    fn retry_with_zero_timeout_tries_once_and_returns() {
        let tries = Cell::new(0);
        let result = retry_faillable_with_timeout(
            || {
                tries.set(tries.get() + 1);
                Ok::<(), ()>(())
            },
            Duration::ZERO,
        );
        assert_eq!(tries.get(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn retry_faillible_with_timeout_tries_until_the_timeout() {
        let tries = Cell::new(0);
        let result: Result<(), ()> = retry_faillable_with_timeout(
            || {
                tries.set(tries.get() + 1);
                Err(())
            },
            Duration::from_millis(25),
        );
        assert!(result.is_err());
        assert!(tries.get() >= 1);
    }

    #[test]
    fn retry_faillible_until_some_with_timeout_returns_ok_none_if_always_ok_none() {
        let result: Result<Option<()>, ()> =
            retry_faillable_until_some_with_timeout(|| Ok(None), Duration::from_millis(25));
        assert_eq!(result, Ok(None));
    }
}
