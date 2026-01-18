use crate::{crypto_utils::CryptoUtils, db_utils::{DbUtils, QueryResult}};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientSender, MixnetMessageSender, ReconstructedMessage,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;
use chrono;
use base64;

/// Sliding window rate limiter to prevent brute-force attacks on authentication endpoints.
/// Tracks attempts per sender_tag within a configurable time window.
struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with specified limits.
    fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_secs,
        }
    }

    /// Check if a request is allowed and record the attempt.
    /// Returns true if allowed, false if rate limited.
    fn check_and_record(&mut self, key: &str) -> bool {
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
    fn cleanup(&mut self) {
        self.attempts.retain(|_, v| !v.is_empty());
    }
}

/// Wrapper for pending entries with TTL support
struct PendingEntry<T> {
    data: T,
    created_at: Instant,
}

impl<T> PendingEntry<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            created_at: Instant::now(),
        }
    }
}

/// Pending user registration data (username, public_key, nonce)
type PendingUserData = (String, String, String);

/// Pending login data (username, public_key, nonce)
type PendingLoginData = (String, String, String);

/// Pending group registration data
struct PendingGroupData {
    group_id: String,
    name: String,
    nym_address: String,
    public_key: String,
    description: Option<String>,
    is_public: bool,
    nonce: String,
}

/// Handler for incoming mixnet messages and command processing.
pub struct MessageUtils {
    db: DbUtils,
    crypto: CryptoUtils,
    sender: MixnetClientSender,
    client_id: String,
    pending_users: HashMap<AnonymousSenderTag, PendingEntry<PendingUserData>>,
    nonces: HashMap<AnonymousSenderTag, PendingEntry<PendingLoginData>>,
    pending_groups: HashMap<AnonymousSenderTag, PendingEntry<PendingGroupData>>,
    /// Rate limiter for authentication endpoints (registration/login)
    rate_limiter: RateLimiter,
}

impl MessageUtils {
    /// Time-to-live for pending entries in seconds (5 minutes)
    const PENDING_TTL_SECS: u64 = 300;

    /// Maximum authentication attempts per sender within the rate limit window
    const RATE_LIMIT_MAX_ATTEMPTS: usize = 10;

    /// Rate limit window in seconds (1 minute)
    const RATE_LIMIT_WINDOW_SECS: u64 = 60;

    /// Create a new MessageUtils instance.
    pub fn new(
        client_id: String,
        sender: MixnetClientSender,
        db: DbUtils,
        crypto: CryptoUtils,
    ) -> Self {
        MessageUtils {
            sender,
            db,
            crypto,
            client_id,
            pending_users: HashMap::new(),
            nonces: HashMap::new(),
            pending_groups: HashMap::new(),
            rate_limiter: RateLimiter::new(
                Self::RATE_LIMIT_MAX_ATTEMPTS,
                Self::RATE_LIMIT_WINDOW_SECS,
            ),
        }
    }

    /// Check if a username is valid: non-empty, max 64 chars, alphanumeric + '-' or '_'.
    fn is_valid_username(username: &str) -> bool {
        !username.is_empty()
            && username.len() <= 64
            && username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Check if a group ID is valid: non-empty, max 128 chars, alphanumeric + '-' or '_'.
    fn is_valid_group_id(group_id: &str) -> bool {
        !group_id.is_empty()
            && group_id.len() <= 128
            && group_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Remove stale entries from all pending HashMaps that exceed the TTL.
    /// This prevents memory leaks from incomplete registration/login flows.
    fn cleanup_stale_entries(&mut self) {
        let now = Instant::now();
        let ttl_secs = Self::PENDING_TTL_SECS;

        let pending_users_before = self.pending_users.len();
        self.pending_users.retain(|_, entry| {
            now.duration_since(entry.created_at).as_secs() < ttl_secs
        });
        let pending_users_removed = pending_users_before - self.pending_users.len();

        let nonces_before = self.nonces.len();
        self.nonces.retain(|_, entry| {
            now.duration_since(entry.created_at).as_secs() < ttl_secs
        });
        let nonces_removed = nonces_before - self.nonces.len();

        let pending_groups_before = self.pending_groups.len();
        self.pending_groups.retain(|_, entry| {
            now.duration_since(entry.created_at).as_secs() < ttl_secs
        });
        let pending_groups_removed = pending_groups_before - self.pending_groups.len();

        let total_removed = pending_users_removed + nonces_removed + pending_groups_removed;
        if total_removed > 0 {
            log::info!(
                "Cleaned up {} stale entries (pending_users: {}, nonces: {}, pending_groups: {})",
                total_removed,
                pending_users_removed,
                nonces_removed,
                pending_groups_removed
            );
        }

        // Clean up rate limiter entries with no recent attempts
        self.rate_limiter.cleanup();
    }

    /// Process an incoming mixnet message.
    pub async fn process_received_message(&mut self, msg: ReconstructedMessage) {
        // Clean up stale pending entries on each message to prevent memory leaks
        self.cleanup_stale_entries();

        let sender_tag = if let Some(tag) = msg.sender_tag {
            tag
        } else {
            log::warn!("Received message without sender tag, ignoring");
            return;
        };
        let raw = match String::from_utf8(msg.message) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Invalid UTF-8 in message: {}", e);
                return;
            }
        };
        let data: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("processReceivedMessage - JSON decode error: {}", e);
                return;
            }
        };
        // Check if this is the new unified format (has "type" field) or old format
        if let Some(message_type) = data.get("type").and_then(Value::as_str) {
            // New unified format
            if let Some(action) = data.get("action").and_then(Value::as_str) {
                log::info!("Processing unified format - type: '{}', action: '{}' from sender_tag={:?}", message_type, action, sender_tag);

                // Extract payload, sender, and recipient for handlers
                let payload = data.get("payload").unwrap_or(&Value::Null);
                let sender_username = data.get("sender").and_then(Value::as_str).unwrap_or("unknown");
                let recipient_username = data.get("recipient").and_then(Value::as_str);

                match action {
                    "query" => self.handle_query_unified(payload, sender_tag, sender_username).await,
                    "register" => self.handle_register_unified(payload, sender_tag, sender_username).await,
                    "registrationResponse" => {
                        self.handle_registration_response_unified(payload, sender_tag).await
                    }
                    "login" => self.handle_login_unified(payload, sender_tag, sender_username).await,
                    "loginResponse" => self.handle_login_response_unified(payload, sender_tag).await,
                    "send" => self.handle_send_unified(payload, sender_tag, sender_username).await,
                    "keyPackageRequest" => self.handle_key_package_request_unified(payload, sender_tag, sender_username, recipient_username).await,
                    "keyPackageResponse" => self.handle_key_package_response_unified(payload, sender_tag, sender_username, recipient_username).await,
                    "groupWelcome" => self.handle_group_welcome_unified(payload, sender_tag, sender_username, recipient_username).await,
                    "groupJoinResponse" => self.handle_group_join_response_unified(payload, sender_tag, sender_username, recipient_username).await,
                    _ => log::error!("Unknown unified action: {}", action),
                }
            } else {
                log::error!("Unified format message missing 'action' field");
            }
        } else if let Some(action) = data.get("action").and_then(Value::as_str) {
            // Legacy format (for backward compatibility during migration)
            log::info!("Processing legacy format action '{}' from sender_tag={:?}", action, sender_tag);
            match action {
                "query" => self.handle_query(&data, sender_tag).await,
                "register" => self.handle_register(&data, sender_tag).await,
                "registrationResponse" => {
                    self.handle_registration_response(&data, sender_tag).await
                }
                "login" => self.handle_login(&data, sender_tag).await,
                "loginResponse" => self.handle_login_response(&data, sender_tag).await,
                "update" => self.handle_update(&data, sender_tag).await,
                "send" => self.handle_send(&data, sender_tag).await,
                "sendGroup" => self.handle_send_group(&data, sender_tag).await,
                "createGroup" => self.handle_create_group(&data, sender_tag).await,
                "inviteGroup" => self.handle_send_invite(&data, sender_tag).await,
                "registerGroup" => self.handle_register_group(&data, sender_tag).await,
                "registerGroupResponse" => self.handle_register_group_response(&data, sender_tag).await,
                "queryGroups" => self.handle_query_groups(&data, sender_tag).await,
                _ => log::error!("Unknown legacy action: {}", action),
            }
        } else {
            log::error!("processReceivedMessage - missing action field");
        }
    }

    async fn handle_query(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        // Support both "username" (legacy) and "identifier" (unified) fields
        let identifier = data.get("identifier")
            .or_else(|| data.get("username"))
            .and_then(Value::as_str);

        if let Some(identifier) = identifier {
            match self.db.query_by_identifier(identifier).await.unwrap_or(None) {
                Some(QueryResult::User { username, public_key, .. }) => {
                    let reply = json!({
                        "type": "user",
                        "username": username,
                        "publicKey": public_key
                    }).to_string();
                    self.send_encapsulated_reply(sender_tag, reply, "queryResponse", Some("query"))
                        .await;
                }
                Some(QueryResult::Group { group_id, name, nym_address, public_key, description }) => {
                    let reply = json!({
                        "type": "group",
                        "groupId": group_id,
                        "name": name,
                        "nymAddress": nym_address,
                        "publicKey": public_key,
                        "description": description
                    }).to_string();
                    self.send_encapsulated_reply(sender_tag, reply, "queryResponse", Some("query"))
                        .await;
                }
                None => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        "No user or group found".into(),
                        "queryResponse",
                        Some("query"),
                    )
                    .await;
                }
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing 'username' or 'identifier' field".into(),
                "queryResponse",
                Some("query"),
            )
            .await;
        }
    }

    async fn handle_register(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        // Rate limit check for registration attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Rate limit exceeded for registration from sender_tag={:?}", sender_tag);
            self.send_encapsulated_reply(
                sender_tag,
                "error: rate limit exceeded, please try again later".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let username = data.get("username").and_then(Value::as_str);
        let public_key = data.get("publicKey").and_then(Value::as_str);
        log::debug!("Registration request - username: {:?}, has_public_key: {}", username, public_key.is_some());
        if username.is_none() || public_key.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing username or public key".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let username = username.unwrap();
        let pubkey = public_key.unwrap();
        if !Self::is_valid_username(username) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: invalid username format".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        if self
            .db
            .get_user_by_username(username)
            .await
            .unwrap_or(None)
            .is_some()
        {
            self.send_encapsulated_reply(
                sender_tag,
                "error: username already in use".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let nonce = Uuid::new_v4().to_string();
        log::debug!("Generated nonce for user '{}': {}", username, nonce);
        self.pending_users.insert(
            sender_tag,
            PendingEntry::new((username.to_string(), pubkey.to_string(), nonce.clone())),
        );
        self.send_encapsulated_reply(
            sender_tag,
            json!({"nonce": nonce}).to_string(),
            "challenge",
            Some("registration"),
        )
        .await;
    }

    async fn handle_registration_response(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let signature = data.get("signature").and_then(Value::as_str);
        log::debug!("Registration response - has_signature: {}", signature.is_some());
        if signature.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing signature".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
            return;
        }
        let signature = signature.unwrap();
        if let Some(entry) = self.pending_users.remove(&sender_tag) {
            let (username, pubkey, nonce) = entry.data;
            log::debug!("Verifying signature for user '{}' with nonce '{}'", username, nonce);
            if self.crypto.verify_signature(&pubkey, &nonce, signature) {
                log::debug!("Signature verification successful for user '{}'", username);
                if self
                    .db
                    .add_user(&username, &pubkey, &sender_tag.to_string())
                    .await
                    .unwrap_or(false)
                {
                    log::info!("Registration successful for user '{}'", username);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "success".into(),
                        "challengeResponse",
                        Some("registration"),
                    )
                    .await;
                } else {
                    log::error!("Database failure during registration for user '{}'", username);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: database failure".into(),
                        "challengeResponse",
                        Some("registration"),
                    )
                    .await;
                }
            } else {
                log::warn!("Signature verification failed for user '{}'", username);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: signature verification failed".into(),
                    "challengeResponse",
                    Some("registration"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: no pending registration".into(),
                "challengeResponse",
                Some("registration"),
            )
            .await;
        }
    }

    async fn handle_login(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        // Rate limit check for login attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Rate limit exceeded for login from sender_tag={:?}", sender_tag);
            self.send_encapsulated_reply(
                sender_tag,
                "error: rate limit exceeded, please try again later".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }

        let username = data.get("username").and_then(Value::as_str);
        if username.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing username".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }
        let username = username.unwrap();
        if let Some((_user, pubkey, _)) =
            self.db.get_user_by_username(username).await.unwrap_or(None)
        {
            let nonce = Uuid::new_v4().to_string();
            self.nonces
                .insert(sender_tag, PendingEntry::new((username.to_string(), pubkey, nonce.clone())));
            self.send_encapsulated_reply(
                sender_tag,
                json!({"nonce": nonce}).to_string(),
                "challenge",
                Some("login"),
            )
            .await;
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: user not found".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
        }
    }

    async fn handle_login_response(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let signature = data.get("signature").and_then(Value::as_str);
        if signature.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing signature".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
            return;
        }
        let signature = signature.unwrap();
        if let Some(entry) = self.nonces.remove(&sender_tag) {
            let (username, pubkey, nonce) = entry.data;
            if self.crypto.verify_signature(&pubkey, &nonce, signature) {
                if let Some((_u, _pk, db_sender_tag)) = self
                    .db
                    .get_user_by_username(&username)
                    .await
                    .unwrap_or(None)
                {
                    if db_sender_tag != sender_tag.to_string() {
                        if let Err(e) = self
                            .db
                            .update_user_field(&username, "senderTag", &sender_tag.to_string())
                            .await
                        {
                            log::warn!("Failed to update senderTag for user {}: {}", username, e);
                        }
                    }
                }
                self.send_encapsulated_reply(
                    sender_tag,
                    "success".into(),
                    "challengeResponse",
                    Some("login"),
                )
                .await;
            } else {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: invalid signature".into(),
                    "challengeResponse",
                    Some("login"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: no pending login".into(),
                "challengeResponse",
                Some("login"),
            )
            .await;
        }
    }

    /// Validates a send request and extracts content/signature.
    /// Returns (content_str, signature, parsed_content) or an error message.
    fn validate_send_request(data: &Value) -> Result<(&str, &str, Value), &'static str> {
        let content_str = data
            .get("content")
            .and_then(Value::as_str)
            .ok_or("error: missing 'content' or 'signature'")?;
        let signature = data
            .get("signature")
            .and_then(Value::as_str)
            .ok_or("error: missing 'content' or 'signature'")?;
        let content: Value = serde_json::from_str(content_str)
            .map_err(|_| "error: invalid JSON in content")?;
        Ok((content_str, signature, content))
    }

    /// Extracts and validates sender/recipient usernames from content.
    fn extract_usernames(content: &Value) -> Result<(&str, &str), &'static str> {
        let sender = content
            .get("sender")
            .and_then(Value::as_str)
            .ok_or("error: missing 'sender' or 'recipient' field")?;
        let recipient = content
            .get("recipient")
            .and_then(Value::as_str)
            .ok_or("error: missing 'sender' or 'recipient' field")?;
        Ok((sender, recipient))
    }

    /// Routes a message to the recipient if they exist.
    async fn route_message_to_recipient(
        &mut self,
        sender_username: &str,
        recipient_username: &str,
        content: &Value,
        sender_tag: AnonymousSenderTag,
    ) {
        let Some((_u2, _pk2, target_sender_tag)) = self
            .db
            .get_user_by_username(recipient_username)
            .await
            .unwrap_or(None)
        else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: recipient not found".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        };

        if let Ok(tag) = AnonymousSenderTag::try_from_base58_string(&target_sender_tag) {
            let mut forward = json!({
                "sender": sender_username,
                "body": content.get("body").cloned().unwrap_or(Value::Null)
            });
            if let Some(spk) = content.get("senderPublicKey") {
                forward["senderPublicKey"] = spk.clone();
            }
            self.send_encapsulated_reply(tag, forward.to_string(), "incomingMessage", Some("chat"))
                .await;
        }

        self.send_encapsulated_reply(sender_tag, "success".into(), "sendResponse", Some("chat"))
            .await;
    }

    async fn handle_send(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        // Validate request and parse content
        let (content_str, signature, content) = match Self::validate_send_request(data) {
            Ok(v) => v,
            Err(msg) => {
                self.send_encapsulated_reply(sender_tag, msg.into(), "sendResponse", Some("chat"))
                    .await;
                return;
            }
        };

        // Extract sender and recipient usernames
        let (sender_username, recipient_username) = match Self::extract_usernames(&content) {
            Ok(v) => v,
            Err(msg) => {
                self.send_encapsulated_reply(sender_tag, msg.into(), "sendResponse", Some("chat"))
                    .await;
                return;
            }
        };

        // Verify sender exists and signature is valid
        let Some((_u, pubkey, db_sender_tag)) = self
            .db
            .get_user_by_username(sender_username)
            .await
            .unwrap_or(None)
        else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: unrecognized sender username".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        };

        if !self.crypto.verify_signature(&pubkey, content_str, signature) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: invalid signature".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        }

        // Update sender tag if changed
        if db_sender_tag != sender_tag.to_string() {
            if let Err(e) = self
                .db
                .update_user_field(sender_username, "senderTag", &sender_tag.to_string())
                .await
            {
                log::warn!("Failed to update senderTag for user {}: {}", sender_username, e);
            }
        }

        // Route message to recipient
        self.route_message_to_recipient(sender_username, recipient_username, &content, sender_tag)
            .await;
    }

    async fn handle_create_group(&mut self, _data: &Value, sender_tag: AnonymousSenderTag) {
        log::warn!("handleCreateGroup - stubs not implemented");
        self.send_encapsulated_reply(
            sender_tag,
            "error: unimplemented".into(),
            "createGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_send_group(&mut self, _data: &Value, sender_tag: AnonymousSenderTag) {
        log::warn!("handleSendGroup - stubs not implemented");
        self.send_encapsulated_reply(
            sender_tag,
            "error: unimplemented".into(),
            "sendGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_send_invite(&mut self, _data: &Value, sender_tag: AnonymousSenderTag) {
        log::warn!("handleSendInvite - stubs not implemented");
        self.send_encapsulated_reply(
            sender_tag,
            "error: unimplemented".into(),
            "inviteGroupResponse",
            None,
        )
        .await;
    }
    async fn handle_update(&mut self, _data: &Value, sender_tag: AnonymousSenderTag) {
        log::warn!("handleUpdate - stubs not implemented");
        self.send_encapsulated_reply(
            sender_tag,
            "error: unimplemented".into(),
            "updateResponse",
            None,
        )
        .await;
    }

    // ===== GROUP SERVER REGISTRATION =====

    /// Handle a group server registration request (step 1: send challenge)
    async fn handle_register_group(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);
        let name = data.get("name").and_then(Value::as_str);
        let nym_address = data.get("nymAddress").and_then(Value::as_str);
        let public_key = data.get("publicKey").and_then(Value::as_str);
        let description = data.get("description").and_then(Value::as_str);
        let is_public = data.get("isPublic").and_then(Value::as_bool).unwrap_or(true);

        log::info!("Group registration request - groupId: {:?}, name: {:?}", group_id, name);

        // Validate required fields
        if group_id.is_none() || name.is_none() || nym_address.is_none() || public_key.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing required fields (groupId, name, nymAddress, publicKey)".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let group_id = group_id.unwrap();
        let name = name.unwrap();
        let nym_address = nym_address.unwrap();
        let public_key = public_key.unwrap();

        // Validate group_id format
        if !Self::is_valid_group_id(group_id) {
            self.send_encapsulated_reply(
                sender_tag,
                "error: invalid groupId format".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        // Check if group already exists
        if let Ok(Some(existing)) = self.db.get_group_by_id(group_id).await {
            // Group exists - check if this is a re-registration (same public key)
            if existing.3 == public_key {
                // Same key - allow address update, send challenge
                log::info!("Group '{}' re-registering with same key, allowing address update", group_id);
            } else {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: groupId already registered with different key".into(),
                    "registerGroupResponse",
                    Some("registration"),
                )
                .await;
                return;
            }
        }

        // Generate nonce for challenge
        let nonce = Uuid::new_v4().to_string();
        log::debug!("Generated nonce for group '{}': {}", group_id, nonce);

        // Store pending registration
        self.pending_groups.insert(
            sender_tag,
            PendingEntry::new(PendingGroupData {
                group_id: group_id.to_string(),
                name: name.to_string(),
                nym_address: nym_address.to_string(),
                public_key: public_key.to_string(),
                description: description.map(String::from),
                is_public,
                nonce: nonce.clone(),
            }),
        );

        // Send challenge
        self.send_encapsulated_reply(
            sender_tag,
            json!({"nonce": nonce}).to_string(),
            "challenge",
            Some("groupRegistration"),
        )
        .await;
    }

    /// Handle group registration response (step 2: verify signature)
    async fn handle_register_group_response(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let signature = data.get("signature").and_then(Value::as_str);

        if signature.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing signature".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
            return;
        }

        let signature = signature.unwrap();

        if let Some(entry) = self.pending_groups.remove(&sender_tag) {
            let pending = entry.data;
            log::debug!("Verifying signature for group '{}' with nonce '{}'", pending.group_id, pending.nonce);

            // Verify signature over the nonce using the group's public key
            if self.crypto.verify_signature(&pending.public_key, &pending.nonce, signature) {
                log::debug!("Signature verification successful for group '{}'", pending.group_id);

                // Check if updating existing or creating new
                let result = if let Ok(Some(_)) = self.db.get_group_by_id(&pending.group_id).await {
                    // Update existing group's address
                    self.db.update_group_address(&pending.group_id, &pending.nym_address).await
                } else {
                    // Add new group
                    self.db.add_group(
                        &pending.group_id,
                        &pending.name,
                        &pending.nym_address,
                        &pending.public_key,
                        pending.description.as_deref(),
                        pending.is_public,
                    ).await
                };

                match result {
                    Ok(true) => {
                        log::info!("Group '{}' registered successfully", pending.group_id);
                        self.send_encapsulated_reply(
                            sender_tag,
                            "success".into(),
                            "registerGroupResponse",
                            Some("registration"),
                        )
                        .await;
                    }
                    _ => {
                        log::error!("Database failure during group registration for '{}'", pending.group_id);
                        self.send_encapsulated_reply(
                            sender_tag,
                            "error: database failure".into(),
                            "registerGroupResponse",
                            Some("registration"),
                        )
                        .await;
                    }
                }
            } else {
                log::warn!("Signature verification failed for group '{}'", pending.group_id);
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: signature verification failed".into(),
                    "registerGroupResponse",
                    Some("registration"),
                )
                .await;
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: no pending group registration".into(),
                "registerGroupResponse",
                Some("registration"),
            )
            .await;
        }
    }

    /// Handle query for discoverable groups
    async fn handle_query_groups(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let group_id = data.get("groupId").and_then(Value::as_str);

        if let Some(gid) = group_id {
            // Query specific group
            match self.db.get_group_by_id(gid).await {
                Ok(Some((id, name, address, public_key, description, is_public))) => {
                    if is_public {
                        let reply = json!({
                            "groups": [{
                                "groupId": id,
                                "name": name,
                                "nymAddress": address,
                                "publicKey": public_key,
                                "description": description
                            }]
                        }).to_string();
                        self.send_encapsulated_reply(sender_tag, reply, "queryGroupsResponse", None).await;
                    } else {
                        self.send_encapsulated_reply(
                            sender_tag,
                            json!({"groups": []}).to_string(),
                            "queryGroupsResponse",
                            None,
                        ).await;
                    }
                }
                _ => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        json!({"groups": []}).to_string(),
                        "queryGroupsResponse",
                        None,
                    ).await;
                }
            }
        } else {
            // Query all public groups
            match self.db.get_public_groups().await {
                Ok(groups) => {
                    let group_list: Vec<Value> = groups
                        .into_iter()
                        .map(|(id, name, address, public_key, description)| {
                            json!({
                                "groupId": id,
                                "name": name,
                                "nymAddress": address,
                                "publicKey": public_key,
                                "description": description
                            })
                        })
                        .collect();
                    let reply = json!({"groups": group_list}).to_string();
                    self.send_encapsulated_reply(sender_tag, reply, "queryGroupsResponse", None).await;
                }
                Err(e) => {
                    log::error!("Failed to query groups: {}", e);
                    self.send_encapsulated_reply(
                        sender_tag,
                        "error: database failure".into(),
                        "queryGroupsResponse",
                        None,
                    ).await;
                }
            }
        }
    }

    // ===== UNIFIED FORMAT HANDLERS =====

    async fn handle_query_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
        // Support both "username" (legacy) and "identifier" (unified) fields
        let identifier = payload.get("identifier")
            .or_else(|| payload.get("username"))
            .and_then(Value::as_str);

        if let Some(identifier) = identifier {
            match self.db.query_by_identifier(identifier).await.unwrap_or(None) {
                Some(QueryResult::User { username, public_key, .. }) => {
                    let response_payload = json!({
                        "type": "user",
                        "username": username,
                        "publicKey": public_key
                    });
                    self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
                }
                Some(QueryResult::Group { group_id, name, nym_address, public_key, description }) => {
                    let response_payload = json!({
                        "type": "group",
                        "groupId": group_id,
                        "name": name,
                        "nymAddress": nym_address,
                        "publicKey": public_key,
                        "description": description
                    });
                    self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
                }
                None => {
                    let response_payload = json!({"error": "No user or group found"});
                    self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
                }
            }
        } else {
            let response_payload = json!({"error": "missing 'username' or 'identifier' field"});
            self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
        }
    }

    async fn handle_register_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
        // Rate limit check for registration attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Rate limit exceeded for unified registration from sender_tag={:?}", sender_tag);
            let response_payload = json!({"result": "error", "context": "registration", "message": "rate limit exceeded, please try again later"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
            return;
        }

        let username = payload.get("username").and_then(Value::as_str);
        let public_key = payload.get("publicKey").and_then(Value::as_str);

        if let (Some(username), Some(public_key)) = (username, public_key) {
            if !Self::is_valid_username(username) {
                let response_payload = json!({"result": "error", "context": "registration", "message": "invalid username"});
                self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
                return;
            }

            if self.db.get_user_by_username(username).await.unwrap_or(None).is_some() {
                let response_payload = json!({"result": "error", "context": "registration", "message": "user already exists"});
                self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
                return;
            }

            // Send challenge
            let nonce = Uuid::new_v4().to_string();
            self.pending_users.insert(sender_tag, PendingEntry::new((username.to_string(), public_key.to_string(), nonce.clone())));

            let challenge_payload = json!({"nonce": nonce, "context": "registration"});
            self.send_unified_reply(sender_tag, challenge_payload, "challenge", sender_username).await;
        } else {
            let response_payload = json!({"result": "error", "context": "registration", "message": "missing username or publicKey"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
        }
    }

    async fn handle_registration_response_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag) {
        let signature = payload.get("signature").and_then(Value::as_str);

        if let Some(signature) = signature {
            if let Some(entry) = self.pending_users.remove(&sender_tag) {
                let (username, public_key, nonce) = entry.data;
                let is_valid = self.crypto.verify_signature(&public_key, &nonce, signature);

                if is_valid {
                    if let Err(e) = self.db.add_user(&username, &public_key, &sender_tag.to_string()).await {
                        log::error!("Failed to register user in DB: {}", e);
                        let response_payload = json!({"result": "error", "context": "registration", "message": "database error"});
                        self.send_unified_reply(sender_tag, response_payload, "challengeResponse", &username).await;
                    } else {
                        log::info!("Successfully registered user '{}' with sender_tag: {}", username, sender_tag);
                        let response_payload = json!({"result": "success", "context": "registration"});
                        self.send_unified_reply(sender_tag, response_payload, "challengeResponse", &username).await;
                    }
                } else {
                    let response_payload = json!({"result": "error", "context": "registration", "message": "invalid signature"});
                    self.send_unified_reply(sender_tag, response_payload, "challengeResponse", &username).await;
                }
            } else {
                let response_payload = json!({"result": "error", "context": "registration", "message": "no pending registration"});
                self.send_unified_reply(sender_tag, response_payload, "challengeResponse", "unknown").await;
            }
        } else {
            let response_payload = json!({"result": "error", "context": "registration", "message": "missing signature"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", "unknown").await;
        }
    }

    async fn handle_login_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
        // Rate limit check for login attempts
        let rate_key = sender_tag.to_string();
        if !self.rate_limiter.check_and_record(&rate_key) {
            log::warn!("Rate limit exceeded for unified login from sender_tag={:?}", sender_tag);
            let response_payload = json!({"result": "error", "context": "login", "message": "rate limit exceeded, please try again later"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
            return;
        }

        let username = payload.get("username").and_then(Value::as_str);
        if let Some(username) = username {
            if let Ok(Some((_, public_key, _))) = self.db.get_user_by_username(username).await {
                let nonce = Uuid::new_v4().to_string();
                self.nonces.insert(sender_tag, PendingEntry::new((username.to_string(), public_key, nonce.clone())));

                let challenge_payload = json!({"nonce": nonce, "context": "login"});
                self.send_unified_reply(sender_tag, challenge_payload, "challenge", sender_username).await;
            } else {
                let response_payload = json!({"result": "error", "context": "login", "message": "user not found"});
                self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
            }
        } else {
            let response_payload = json!({"result": "error", "context": "login", "message": "missing username"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", sender_username).await;
        }
    }

    async fn handle_login_response_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag) {
        let signature = payload.get("signature").and_then(Value::as_str);

        if let Some(signature) = signature {
            if let Some(entry) = self.nonces.remove(&sender_tag) {
                let (username, public_key, nonce) = entry.data;
                let is_valid = self.crypto.verify_signature(&public_key, &nonce, signature);

                if is_valid {
                    // Update the user's senderTag since ephemeral clients change addresses each session
                    if let Err(e) = self.db.update_user_field(&username, "senderTag", &sender_tag.to_string()).await {
                        log::error!("Failed to update senderTag for user '{}': {}", username, e);
                    } else {
                        log::info!("Updated senderTag for user '{}' to: {}", username, sender_tag);
                    }

                    let response_payload = json!({"result": "success", "context": "login"});
                    self.send_unified_reply(sender_tag, response_payload, "challengeResponse", &username).await;
                } else {
                    let response_payload = json!({"result": "error", "context": "login", "message": "invalid signature"});
                    self.send_unified_reply(sender_tag, response_payload, "challengeResponse", &username).await;
                }
            } else {
                let response_payload = json!({"result": "error", "context": "login", "message": "no pending login"});
                self.send_unified_reply(sender_tag, response_payload, "challengeResponse", "unknown").await;
            }
        } else {
            let response_payload = json!({"result": "error", "context": "login", "message": "missing signature"});
            self.send_unified_reply(sender_tag, response_payload, "challengeResponse", "unknown").await;
        }
    }

    async fn handle_send_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
        log::debug!("Received unified send message from {} with payload: {}", sender_username, payload);

        // For MLS messages, extract conversation_id and mls_message
        if let (Some(conversation_id), Some(_mls_message)) = (
            payload.get("conversation_id").and_then(Value::as_str),
            payload.get("mls_message").and_then(Value::as_str)
        ) {
            log::info!("Routing MLS encrypted message from {} (conversation: {})", sender_username, conversation_id);

            // TODO: Extract recipient from conversation_id or maintain routing table
            // For now, we need to determine the recipient from the conversation_id format "sender-recipient"
            let conversation_decoded = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, conversation_id.as_bytes()) {
                Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
                Err(_) => conversation_id.to_string()
            };

            // Extract recipient from conversation format "sender-recipient"
            let parts: Vec<&str> = conversation_decoded.split('-').collect();
            if parts.len() >= 2 {
                let recipient = if parts[0] == sender_username { parts[1] } else { parts[0] };

                // Look up recipient's Nym address and forward message
                if let Ok(Some((_username, _public_key, target_sender_tag))) = self.db.get_user_by_username(recipient).await {
                    if let Ok(recipient_tag) = AnonymousSenderTag::try_from_base58_string(&target_sender_tag) {
                        // Forward the MLS encrypted payload as-is
                        let message_payload = payload.clone();

                        // Forward message to recipient using unified format (type: "message", action: "send")
                        self.send_unified_message(recipient_tag, message_payload, "send", recipient, sender_username).await;
                        log::info!("Successfully forwarded MLS message from {} to {}", sender_username, recipient);

                        // Send success response to sender
                        let response_payload = json!({
                            "status": "delivered",
                            "recipient": recipient,
                            "message": "Message delivered successfully"
                        });
                        self.send_unified_reply(sender_tag, response_payload, "sendResponse", sender_username).await;
                    } else {
                        log::error!("Invalid sender tag for recipient {}: {}", recipient, target_sender_tag);
                        let response_payload = json!({"status": "error", "message": "recipient address invalid"});
                        self.send_unified_reply(sender_tag, response_payload, "sendResponse", sender_username).await;
                    }
                } else {
                    log::info!("Recipient {} not found in database", recipient);
                    let response_payload = json!({"status": "error", "message": "recipient not found"});
                    self.send_unified_reply(sender_tag, response_payload, "sendResponse", sender_username).await;
                }
            } else {
                log::error!("Invalid conversation_id format: {}", conversation_decoded);
                let response_payload = json!({"status": "error", "message": "invalid conversation format"});
                self.send_unified_reply(sender_tag, response_payload, "sendResponse", sender_username).await;
            }
        } else {
            let response_payload = json!({"status": "error", "message": "missing conversation_id or mls_message"});
            self.send_unified_reply(sender_tag, response_payload, "sendResponse", sender_username).await;
        }
    }

    async fn handle_key_package_request_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
        log::info!("Handling key package request from {}", sender_username);

        // Use the recipient from the message structure
        if let Some(recipient) = recipient_username {
            // Route the key package request to the intended recipient
            if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
                log::info!("Routing key package request from {} to {}", sender_username, recipient);
                self.send_unified_message(recipient_tag, payload.clone(), "keyPackageRequest", recipient, sender_username).await;
            } else {
                log::warn!("Recipient {} not found for key package request", recipient);
                let error_payload = json!({
                    "status": "error",
                    "message": format!("Recipient {} not found or offline", recipient)
                });
                self.send_unified_reply(sender_tag, error_payload, "keyPackageResponse", sender_username).await;
            }
        } else {
            log::error!("Key package request missing recipient field");
            let error_payload = json!({
                "status": "error",
                "message": "Missing recipient field"
            });
            self.send_unified_reply(sender_tag, error_payload, "keyPackageResponse", sender_username).await;
        }
    }

    async fn handle_key_package_response_unified(&mut self, payload: &Value, _sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
        log::info!("Handling key package response from {}", sender_username);

        // Route the key package response back to the original requester
        if let Some(recipient) = recipient_username {
            if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
                log::info!("Routing key package response from {} to {}", sender_username, recipient);
                self.send_unified_message(recipient_tag, payload.clone(), "keyPackageResponse", recipient, sender_username).await;
            } else {
                log::warn!("Original requester {} not found for key package response", recipient);
            }
        } else {
            log::error!("Key package response missing recipient field");
        }
    }

    async fn handle_group_welcome_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
        log::info!("Handling group welcome message from {}", sender_username);

        // Route the group welcome message to the intended recipient
        if let Some(recipient) = recipient_username {
            if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
                log::info!("Routing group welcome from {} to {}", sender_username, recipient);
                self.send_unified_message(recipient_tag, payload.clone(), "groupWelcome", recipient, sender_username).await;
            } else {
                log::warn!("Recipient {} not found for group welcome", recipient);
                let error_payload = json!({
                    "status": "error",
                    "message": format!("Recipient {} not found or offline", recipient)
                });
                self.send_unified_reply(sender_tag, error_payload, "groupJoinResponse", sender_username).await;
            }
        } else {
            log::error!("Group welcome message missing recipient field");
            let error_payload = json!({
                "status": "error",
                "message": "Missing recipient field"
            });
            self.send_unified_reply(sender_tag, error_payload, "groupJoinResponse", sender_username).await;
        }
    }

    async fn handle_group_join_response_unified(&mut self, payload: &Value, _sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
        log::info!("Handling group join response from {}", sender_username);

        // Route the group join response back to the group creator
        if let Some(recipient) = recipient_username {
            if let Some(recipient_tag) = self.get_user_sender_tag(recipient).await {
                log::info!("Routing group join response from {} to {}", sender_username, recipient);
                self.send_unified_message(recipient_tag, payload.clone(), "groupJoinResponse", recipient, sender_username).await;
            } else {
                log::warn!("Group creator {} not found for join response", recipient);
            }
        } else {
            log::error!("Group join response missing recipient field");
        }
    }

    async fn get_user_sender_tag(&self, username: &str) -> Option<AnonymousSenderTag> {
        if let Ok(Some((_username, _public_key, target_sender_tag))) = self.db.get_user_by_username(username).await {
            if let Ok(recipient_tag) = AnonymousSenderTag::try_from_base58_string(&target_sender_tag) {
                return Some(recipient_tag);
            }
        }
        None
    }

    /// Send a unified format reply
    async fn send_unified_reply(
        &self,
        recipient: AnonymousSenderTag,
        payload: Value,
        action: &str,
        recipient_username: &str,
    ) {
        log::info!("Sending unified reply action '{}' to sender_tag={:?}", action, recipient);

        // Create unified format response
        let message = json!({
            "type": "response",
            "action": action,
            "sender": "server",
            "recipient": recipient_username,
            "payload": payload,
            "signature": "server_signature",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        // Sign the payload
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &payload_str) {
            let mut signed_message = message;
            signed_message["signature"] = json!(signature);

            let msg_str = signed_message.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg_str).await {
                log::warn!("Failed to send unified reply: {}", e);
            }
        } else {
            log::error!("Failed to sign unified reply message");
        }
    }

    /// Send a unified format message (type: "message")
    async fn send_unified_message(
        &self,
        recipient: AnonymousSenderTag,
        payload: Value,
        action: &str,
        recipient_username: &str,
        sender_username: &str,
    ) {
        log::info!("Sending unified message action '{}' to sender_tag={:?}", action, recipient);

        // Create unified format message (type: "message" for forwarded messages)
        let message = json!({
            "type": "message",
            "action": action,
            "sender": sender_username,
            "recipient": recipient_username,
            "payload": payload,
            "signature": "server_signature",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        // Sign the payload
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &payload_str) {
            let mut signed_message = message;
            signed_message["signature"] = json!(signature);

            let msg_str = signed_message.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg_str).await {
                log::warn!("Failed to send unified message: {}", e);
            }
        } else {
            log::error!("Failed to sign unified message");
        }
    }

    /// Sign and send a JSON reply over the mixnet using SURBs.
    async fn send_encapsulated_reply(
        &self,
        recipient: AnonymousSenderTag,
        content: String,
        action: &str,
        context: Option<&str>,
    ) {
        log::info!("Sending action '{}' to sender_tag={:?}, context={:?}", action, recipient, context);
        let mut payload = json!({"action": action, "content": content});
        if let Some(ctx) = context {
            payload["context"] = json!(ctx);
        }
        let to_sign = payload["content"].as_str().unwrap_or_default().to_string();
        if let Ok(signature) = self.crypto.sign_message(&self.client_id, &to_sign) {
            payload["signature"] = json!(signature);
            let msg = payload.to_string();
            if let Err(e) = self.sender.send_reply(recipient, msg).await {
                log::warn!("Failed to send encapsulated reply: {}", e);
            }
        } else {
            log::error!("sendEncapsulatedReply - failed to sign message");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_username() {
        assert!(MessageUtils::is_valid_username("valid_user123"));
        assert!(MessageUtils::is_valid_username("user-name"));
        assert!(MessageUtils::is_valid_username("user_name"));
        assert!(MessageUtils::is_valid_username("123user"));
        // Max length (64 chars)
        assert!(MessageUtils::is_valid_username(&"a".repeat(64)));

        assert!(!MessageUtils::is_valid_username(""));
        assert!(!MessageUtils::is_valid_username("invalid user"));
        assert!(!MessageUtils::is_valid_username("user@domain"));
        assert!(!MessageUtils::is_valid_username("user.name"));
        assert!(!MessageUtils::is_valid_username("user%name"));
        // Over max length (65 chars)
        assert!(!MessageUtils::is_valid_username(&"a".repeat(65)));
    }

    #[test]
    fn test_is_valid_group_id() {
        assert!(MessageUtils::is_valid_group_id("valid-group-123"));
        assert!(MessageUtils::is_valid_group_id("group_name"));
        assert!(MessageUtils::is_valid_group_id("GroupName123"));
        // Max length (128 chars)
        assert!(MessageUtils::is_valid_group_id(&"a".repeat(128)));

        assert!(!MessageUtils::is_valid_group_id(""));
        assert!(!MessageUtils::is_valid_group_id("invalid group"));
        assert!(!MessageUtils::is_valid_group_id("group@id"));
        assert!(!MessageUtils::is_valid_group_id("group.id"));
        // Over max length (129 chars)
        assert!(!MessageUtils::is_valid_group_id(&"a".repeat(129)));
    }
}
