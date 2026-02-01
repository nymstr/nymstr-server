//! Pending entry types for tracking in-progress operations.
//!
//! These types wrap data with TTL support for automatic cleanup.

use std::time::Instant;

/// Wrapper for pending entries with TTL support
pub struct PendingEntry<T> {
    pub data: T,
    pub created_at: Instant,
}

impl<T> PendingEntry<T> {
    pub fn new(data: T) -> Self {
        Self {
            data,
            created_at: Instant::now(),
        }
    }
}

/// Pending user registration data (username, public_key, nonce)
pub type PendingUserData = (String, String, String);

/// Pending login data (username, public_key, nonce)
pub type PendingLoginData = (String, String, String);

/// Pending group registration data
pub struct PendingGroupData {
    pub group_id: String,
    pub name: String,
    pub nym_address: String,
    pub public_key: String,
    pub description: Option<String>,
    pub is_public: bool,
    pub nonce: String,
}
