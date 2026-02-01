//! Standardized response formatting for the discovery server.
//!
//! Provides consistent error codes and response formats for all endpoints.

use serde_json::{json, Value};

/// Standardized error response codes
#[allow(dead_code)]
pub mod error_codes {
    pub const MISSING_FIELDS: &str = "MISSING_FIELDS";
    pub const INVALID_USERNAME: &str = "INVALID_USERNAME";
    pub const INVALID_GROUP_ID: &str = "INVALID_GROUP_ID";
    pub const USER_EXISTS: &str = "USER_EXISTS";
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const INVALID_SIGNATURE: &str = "INVALID_SIGNATURE";
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const INVALID_FORMAT: &str = "INVALID_FORMAT";
}

/// Create a standardized error response JSON
pub fn error_response(code: &str, message: &str) -> String {
    json!({
        "status": "error",
        "error_code": code,
        "message": message
    })
    .to_string()
}

/// Create a standardized success response JSON with data
#[allow(dead_code)]
pub fn success_response(data: Value) -> String {
    json!({
        "status": "success",
        "data": data
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_format() {
        let response = error_response(error_codes::MISSING_FIELDS, "Username required");
        let parsed: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["error_code"], "MISSING_FIELDS");
        assert_eq!(parsed["message"], "Username required");
    }

    #[test]
    fn test_success_response_format() {
        let data = json!({"username": "alice", "publicKey": "abc123"});
        let response = success_response(data);
        let parsed: Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["status"], "success");
        assert_eq!(parsed["data"]["username"], "alice");
    }
}
