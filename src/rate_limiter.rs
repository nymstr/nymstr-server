//! Rate limiting for authentication endpoints.
//!
//! Provides a sliding window rate limiter to prevent brute-force attacks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sliding window rate limiter to prevent brute-force attacks on authentication endpoints.
/// Tracks attempts per sender_tag within a configurable time window.
pub struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with specified limits.
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    /// Check if a request is allowed and record the attempt.
    /// Returns true if allowed, false if rate limited.
    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        let attempts = self.attempts.entry(key.to_string()).or_default();
        // Remove old attempts outside the window
        attempts.retain(|&t| now.duration_since(t) < window);

        if attempts.len() >= self.max_attempts {
            return false; // Rate limited
        }

        attempts.push(now);
        true // Allowed
    }

    /// Remove empty entries to prevent memory growth.
    pub fn cleanup(&mut self) {
        self.attempts.retain(|_, v| !v.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(3, 60);
        assert!(limiter.check_and_record("test"));
        assert!(limiter.check_and_record("test"));
        assert!(limiter.check_and_record("test"));
    }

    #[test]
    fn test_rate_limiter_blocks_at_limit() {
        let mut limiter = RateLimiter::new(2, 60);
        assert!(limiter.check_and_record("test"));
        assert!(limiter.check_and_record("test"));
        assert!(!limiter.check_and_record("test")); // Should be blocked
    }

    #[test]
    fn test_rate_limiter_separate_keys() {
        let mut limiter = RateLimiter::new(1, 60);
        assert!(limiter.check_and_record("key1"));
        assert!(!limiter.check_and_record("key1")); // Blocked
        assert!(limiter.check_and_record("key2")); // Different key, allowed
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let mut limiter = RateLimiter::new(10, 60);
        limiter.check_and_record("test");
        assert!(!limiter.attempts.is_empty());

        // Manually clear the attempts to simulate expiry
        limiter.attempts.get_mut("test").unwrap().clear();
        limiter.cleanup();
        assert!(limiter.attempts.is_empty());
    }
}
