use std::time::Duration;

/// Policy for retrying operations with exponential backoff.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of retries allowed.
    pub max_retries: u32,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Multiplier for the delay after each retry.
    pub multiplier: f64,
    /// Maximum delay allowed between retries.
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
