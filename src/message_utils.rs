use crate::{crypto_utils::CryptoUtils, db_utils::DbUtils};
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientSender, MixnetMessageSender, ReconstructedMessage,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
use chrono;
use base64;

/// Handler for incoming mixnet messages and command processing.
pub struct MessageUtils {
    db: DbUtils,
    crypto: CryptoUtils,
    sender: MixnetClientSender,
    client_id: String,
    pending_users: HashMap<AnonymousSenderTag, (String, String, String)>,
    nonces: HashMap<AnonymousSenderTag, (String, String, String)>,
}

impl MessageUtils {
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
        }
    }

    /// Check if a username is valid: only alphanumeric, '-' or '_'.
    fn is_valid_username(username: &str) -> bool {
        !username.is_empty()
            && username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Process an incoming mixnet message.
    pub async fn process_received_message(&mut self, msg: ReconstructedMessage) {
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
                _ => log::error!("Unknown legacy action: {}", action),
            }
        } else {
            log::error!("processReceivedMessage - missing action field");
        }
    }

    async fn handle_query(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        if let Some(username) = data.get("username").and_then(Value::as_str) {
            match self.db.get_user_by_username(username).await.unwrap_or(None) {
                Some((user, pubkey, _)) => {
                    let reply = json!({"username": user, "publicKey": pubkey}).to_string();
                    self.send_encapsulated_reply(sender_tag, reply, "queryResponse", Some("query"))
                        .await;
                }
                None => {
                    self.send_encapsulated_reply(
                        sender_tag,
                        "No user found".into(),
                        "queryResponse",
                        Some("query"),
                    )
                    .await;
                }
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing 'username' field".into(),
                "queryResponse",
                Some("query"),
            )
            .await;
        }
    }

    async fn handle_register(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
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
            (username.to_string(), pubkey.to_string(), nonce.clone()),
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
        if let Some((username, pubkey, nonce)) = self.pending_users.remove(&sender_tag) {
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
                .insert(sender_tag, (username.to_string(), pubkey, nonce.clone()));
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
        if let Some((username, pubkey, nonce)) = self.nonces.remove(&sender_tag) {
            if self.crypto.verify_signature(&pubkey, &nonce, signature) {
                if let Some((_u, _pk, db_sender_tag)) = self
                    .db
                    .get_user_by_username(&username)
                    .await
                    .unwrap_or(None)
                {
                    if db_sender_tag != sender_tag.to_string() {
                        let _ = self
                            .db
                            .update_user_field(&username, "senderTag", &sender_tag.to_string())
                            .await;
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

    async fn handle_send(&mut self, data: &Value, sender_tag: AnonymousSenderTag) {
        let content_str = data.get("content").and_then(Value::as_str);
        let signature = data.get("signature").and_then(Value::as_str);
        if content_str.is_none() || signature.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing 'content' or 'signature'".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        }
        let content_str = content_str.unwrap();
        let signature = signature.unwrap();
        let content: Value = match serde_json::from_str(content_str) {
            Ok(v) => v,
            Err(_) => {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: invalid JSON in content".into(),
                    "sendResponse",
                    Some("chat"),
                )
                .await;
                return;
            }
        };
        let sender_username = content.get("sender").and_then(Value::as_str);
        let recipient_username = content.get("recipient").and_then(Value::as_str);
        if sender_username.is_none() || recipient_username.is_none() {
            self.send_encapsulated_reply(
                sender_tag,
                "error: missing 'sender' or 'recipient' field".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        }
        let sender_username = sender_username.unwrap();
        let recipient_username = recipient_username.unwrap();
        if let Some((_u, pubkey, db_sender_tag)) = self
            .db
            .get_user_by_username(sender_username)
            .await
            .unwrap_or(None)
        {
            if !self
                .crypto
                .verify_signature(&pubkey, content_str, signature)
            {
                self.send_encapsulated_reply(
                    sender_tag,
                    "error: invalid signature".into(),
                    "sendResponse",
                    Some("chat"),
                )
                .await;
                return;
            }
            if db_sender_tag != sender_tag.to_string() {
                let _ = self
                    .db
                    .update_user_field(sender_username, "senderTag", &sender_tag.to_string())
                    .await;
            }
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: unrecognized sender username".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
            return;
        }
        if let Some((_u2, _pk2, target_sender_tag)) = self
            .db
            .get_user_by_username(recipient_username)
            .await
            .unwrap_or(None)
        {
            if let Ok(tag) = AnonymousSenderTag::try_from_base58_string(&target_sender_tag) {
                let mut forward = json!({"sender": sender_username, "body": content.get("body").cloned().unwrap_or(Value::Null)});
                if let Some(spk) = content.get("senderPublicKey") {
                    forward["senderPublicKey"] = spk.clone();
                }
                self.send_encapsulated_reply(
                    tag,
                    forward.to_string(),
                    "incomingMessage",
                    Some("chat"),
                )
                .await;
            }
            self.send_encapsulated_reply(
                sender_tag,
                "success".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
        } else {
            self.send_encapsulated_reply(
                sender_tag,
                "error: recipient not found".into(),
                "sendResponse",
                Some("chat"),
            )
            .await;
        }
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

    // ===== UNIFIED FORMAT HANDLERS =====

    async fn handle_query_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
        if let Some(username) = payload.get("username").and_then(Value::as_str) {
            match self.db.get_user_by_username(username).await.unwrap_or(None) {
                Some((user, pubkey, _)) => {
                    let response_payload = json!({"username": user, "publicKey": pubkey});
                    self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
                }
                None => {
                    let response_payload = json!({"error": "No user found"});
                    self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
                }
            }
        } else {
            let response_payload = json!({"error": "missing 'username' field"});
            self.send_unified_reply(sender_tag, response_payload, "queryResponse", sender_username).await;
        }
    }

    async fn handle_register_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str) {
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
            self.pending_users.insert(sender_tag, (username.to_string(), public_key.to_string(), nonce.clone()));

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
            if let Some((username, public_key, nonce)) = self.pending_users.remove(&sender_tag) {
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
        let username = payload.get("username").and_then(Value::as_str);
        if let Some(username) = username {
            if let Ok(Some((_, public_key, _))) = self.db.get_user_by_username(username).await {
                let nonce = Uuid::new_v4().to_string();
                self.nonces.insert(sender_tag, (username.to_string(), public_key, nonce.clone()));

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
            if let Some((username, public_key, nonce)) = self.nonces.remove(&sender_tag) {
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
        log::info!("Received unified send message from {} with payload: {}", sender_username, payload);

        // For MLS messages, extract conversation_id and mls_message
        if let (Some(conversation_id), Some(mls_message)) = (
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

    async fn handle_key_package_response_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
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

    async fn handle_group_join_response_unified(&mut self, payload: &Value, sender_tag: AnonymousSenderTag, sender_username: &str, recipient_username: Option<&str>) {
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
            let _ = self.sender.send_reply(recipient, msg_str).await;
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
            let _ = self.sender.send_reply(recipient, msg_str).await;
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
            let _ = self.sender.send_reply(recipient, msg).await;
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
        
        assert!(!MessageUtils::is_valid_username(""));
        assert!(!MessageUtils::is_valid_username("invalid user"));
        assert!(!MessageUtils::is_valid_username("user@domain"));
        assert!(!MessageUtils::is_valid_username("user.name"));
        assert!(!MessageUtils::is_valid_username("user%name"));
    }
}
