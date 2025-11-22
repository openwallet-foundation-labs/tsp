use std::time::Duration;

/// Policy for retrying operations with exponential backoff.
///
/// This struct defines the parameters for the retry mechanism, controlling
/// how many times to retry and how long to wait between attempts.
///
/// # Example
///
/// ```
/// use tsp_sdk::retry::RetryPolicy;
/// use std::time::Duration;
///
/// let policy = RetryPolicy {
///     max_retries: 3,
///     initial_delay: Duration::from_millis(100),
///     multiplier: 2.0,
///     max_delay: Duration::from_secs(1),
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of retries allowed.
    pub max_retries: u32,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Multiplier for the delay after each retry.
    ///
    /// e.g., if `initial_delay` is 1s and `multiplier` is 2.0,
    /// the delays will be 1s, 2s, 4s...
    pub multiplier: f64,
    /// Maximum delay allowed between retries.
    ///
    /// This caps the exponential growth to prevent excessively long waits.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            multiplier: 1.5,
            max_delay: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    /// Calculate the timeout duration for the next retry attempt.
    ///
    /// Returns `None` if the `retry_count` has reached or exceeded `max_retries`.
    /// Otherwise, returns `Some(duration)` where duration is calculated as:
    /// `min(initial_delay * multiplier^retry_count, max_delay)`
    pub fn next_timeout(&self, retry_count: u32) -> Option<Duration> {
        if retry_count >= self.max_retries {
            return None;
        }

        let delay = self.initial_delay.as_secs_f64() * self.multiplier.powi(retry_count as i32);
        let delay = Duration::from_secs_f64(delay);

        Some(std::cmp::min(delay, self.max_delay))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let policy = RetryPolicy {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            multiplier: 2.0,
            max_delay: Duration::from_secs(10),
        };

        assert_eq!(policy.next_timeout(0), Some(Duration::from_secs(1)));
        assert_eq!(policy.next_timeout(1), Some(Duration::from_secs(2)));
        assert_eq!(policy.next_timeout(2), Some(Duration::from_secs(4)));
        assert_eq!(policy.next_timeout(3), None);
    }

    #[test]
    fn test_max_delay() {
        let policy = RetryPolicy {
            max_retries: 5,
            initial_delay: Duration::from_secs(1),
            multiplier: 10.0,
            max_delay: Duration::from_secs(5),
        };

        assert_eq!(policy.next_timeout(0), Some(Duration::from_secs(1)));
        assert_eq!(policy.next_timeout(1), Some(Duration::from_secs(5))); // Capped
    }
}
