use anyhow::Result;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::time::Duration;

/// Result of a unified query - can be either a user or a group
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are used in pattern matching
pub enum QueryResult {
    User {
        username: String,
        public_key: String,
        sender_tag: String,
    },
    Group {
        group_id: String,
        name: String,
        nym_address: String,
        public_key: String,
        description: Option<String>,
    },
}

#[derive(Clone)]
pub struct DbUtils {
    pool: SqlitePool,
}

impl DbUtils {
    /// Open or create the SQLite database at the specified path.
    ///
    /// Configures the connection pool with:
    /// - max 5 connections (appropriate for SQLite's single-writer model)
    /// - 3 second acquire timeout to fail fast on overload
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_url = format!("sqlite:{}?mode=rwc", db_path.as_ref().display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&db_url)
            .await?;
        sqlx::query(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                username   TEXT PRIMARY KEY,
                publicKey  TEXT NOT NULL,
                senderTag  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                groupId      TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                nymAddress   TEXT NOT NULL,
                publicKey    TEXT NOT NULL,
                description  TEXT,
                isPublic     INTEGER NOT NULL DEFAULT 1,
                createdAt    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_groups_public ON groups(isPublic);

            CREATE TABLE IF NOT EXISTS pending_messages (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient    TEXT NOT NULL,
                sender       TEXT NOT NULL,
                payload      TEXT NOT NULL,
                action       TEXT NOT NULL DEFAULT 'send',
                createdAt    INTEGER NOT NULL DEFAULT (unixepoch()),
                expiresAt    INTEGER NOT NULL DEFAULT (unixepoch() + 604800)
            );
            CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_messages(recipient);
            CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending_messages(expiresAt);
            "#,
        )
        .execute(&pool)
        .await?;
        Ok(DbUtils { pool })
    }

    /// Retrieve a user by username. Returns (username, publicKey, senderTag).
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<(String, String, String)>> {
        let row =
            sqlx::query("SELECT username, publicKey, senderTag FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
    }

    /// Register a new user (alias for add_user with empty sender_tag)
    #[allow(dead_code)] // Part of public API for future use
    pub async fn register_user(&self, username: &str, public_key: &str) -> Result<()> {
        self.add_user(username, public_key, "").await?;
        Ok(())
    }

    /// Add a new user. Returns true on success.
    pub async fn add_user(
        &self,
        username: &str,
        public_key: &str,
        sender_tag: &str,
    ) -> Result<bool> {
        let res =
            sqlx::query("INSERT INTO users (username, publicKey, senderTag) VALUES (?, ?, ?)")
                .bind(username)
                .bind(public_key)
                .bind(sender_tag)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Validate that a field name is allowed for user updates.
    /// Only publicKey and senderTag can be updated (username is the primary key).
    fn validate_user_update_field(field: &str) -> Result<&str> {
        match field {
            "publicKey" | "senderTag" => Ok(field),
            _ => Err(anyhow::anyhow!("Invalid field name for user update: {}", field)),
        }
    }

    /// Update a single field of a user. Returns true on success.
    /// Only publicKey and senderTag fields are allowed to prevent SQL injection.
    pub async fn update_user_field(
        &self,
        username: &str,
        field: &str,
        value: &str,
    ) -> Result<bool> {
        let validated_field = Self::validate_user_update_field(field)?;
        let sql = format!("UPDATE users SET {} = ? WHERE username = ?", validated_field);
        let res = sqlx::query(&sql)
            .bind(value)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    // ===== GROUP OPERATIONS =====

    /// Register a new group. Returns true on success.
    pub async fn add_group(
        &self,
        group_id: &str,
        name: &str,
        nym_address: &str,
        public_key: &str,
        description: Option<&str>,
        is_public: bool,
    ) -> Result<bool> {
        let created_at = chrono::Utc::now().to_rfc3339();
        let res = sqlx::query(
            "INSERT INTO groups (groupId, name, nymAddress, publicKey, description, isPublic, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(group_id)
        .bind(name)
        .bind(nym_address)
        .bind(public_key)
        .bind(description)
        .bind(is_public as i64)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get a group by ID. Returns (groupId, name, nymAddress, publicKey, description, isPublic).
    pub async fn get_group_by_id(
        &self,
        group_id: &str,
    ) -> Result<Option<(String, String, String, String, Option<String>, bool)>> {
        let row = sqlx::query(
            "SELECT groupId, name, nymAddress, publicKey, description, isPublic FROM groups WHERE groupId = ?"
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            (
                r.get(0),
                r.get(1),
                r.get(2),
                r.get(3),
                r.get(4),
                r.get::<i64, _>(5) != 0,
            )
        }))
    }

    /// Get all public groups. Returns Vec<(groupId, name, nymAddress, publicKey, description)>.
    pub async fn get_public_groups(&self) -> Result<Vec<(String, String, String, String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT groupId, name, nymAddress, publicKey, description FROM groups WHERE isPublic = 1 ORDER BY createdAt DESC"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4))).collect())
    }

    /// Update a group's Nym address (for re-registration after restart).
    pub async fn update_group_address(&self, group_id: &str, nym_address: &str) -> Result<bool> {
        let res = sqlx::query("UPDATE groups SET nymAddress = ? WHERE groupId = ?")
            .bind(nym_address)
            .bind(group_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    // ===== UNIFIED QUERY =====

    /// Query by identifier - checks users first, then public groups.
    /// Returns QueryResult::User or QueryResult::Group if found.
    pub async fn query_by_identifier(&self, identifier: &str) -> Result<Option<QueryResult>> {
        // First check if it's a user
        if let Some((username, public_key, sender_tag)) = self.get_user_by_username(identifier).await? {
            return Ok(Some(QueryResult::User {
                username,
                public_key,
                sender_tag,
            }));
        }

        // Then check if it's a public group
        if let Some((group_id, name, nym_address, public_key, description, is_public)) =
            self.get_group_by_id(identifier).await?
        {
            if is_public {
                return Ok(Some(QueryResult::Group {
                    group_id,
                    name,
                    nym_address,
                    public_key,
                    description,
                }));
            }
        }

        Ok(None)
    }

    // ===== PENDING MESSAGE OPERATIONS =====

    /// Queue a message for an offline user. Returns the message ID.
    pub async fn queue_pending_message(
        &self,
        recipient: &str,
        sender: &str,
        payload: &str,
        action: &str,
    ) -> Result<i64> {
        let res = sqlx::query(
            "INSERT INTO pending_messages (recipient, sender, payload, action) VALUES (?, ?, ?, ?)"
        )
        .bind(recipient)
        .bind(sender)
        .bind(payload)
        .bind(action)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Get all pending messages for a user. Returns Vec<(id, sender, payload, action, createdAt)>.
    pub async fn get_pending_messages(
        &self,
        recipient: &str,
    ) -> Result<Vec<(i64, String, String, String, i64)>> {
        let rows = sqlx::query(
            "SELECT id, sender, payload, action, createdAt FROM pending_messages WHERE recipient = ? AND expiresAt > unixepoch() ORDER BY createdAt ASC"
        )
        .bind(recipient)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4))).collect())
    }

    /// Delete pending messages by IDs after successful delivery.
    pub async fn delete_pending_messages(&self, ids: &[i64]) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM pending_messages WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut query = sqlx::query(&sql);
        for id in ids {
            query = query.bind(id);
        }
        let res = query.execute(&self.pool).await?;
        Ok(res.rows_affected())
    }

    /// Cleanup expired messages. Call periodically.
    pub async fn cleanup_expired_messages(&self) -> Result<u64> {
        let res = sqlx::query("DELETE FROM pending_messages WHERE expiresAt < unixepoch()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Get count of pending messages for a user (useful for status).
    pub async fn get_pending_message_count(&self, recipient: &str) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM pending_messages WHERE recipient = ? AND expiresAt > unixepoch()"
        )
        .bind(recipient)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio_test;

    #[tokio::test]
    async fn test_new_creates_database_and_tables() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        
        let _db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        assert!(db_path.exists());
    }

    #[tokio::test]
    async fn test_add_and_get_user() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let username = "test_user";
        let public_key = "test_public_key";
        let sender_tag = "test_sender_tag";
        
        let added = db.add_user(username, public_key, sender_tag).await.unwrap();
        assert!(added);
        
        let user = db.get_user_by_username(username).await.unwrap();
        assert!(user.is_some());
        
        let (db_username, db_public_key, db_sender_tag) = user.unwrap();
        assert_eq!(db_username, username);
        assert_eq!(db_public_key, public_key);
        assert_eq!(db_sender_tag, sender_tag);
    }

    #[tokio::test]
    async fn test_get_nonexistent_user() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let user = db.get_user_by_username("nonexistent_user").await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_add_duplicate_user() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let username = "test_user";
        let public_key = "test_public_key";
        let sender_tag = "test_sender_tag";
        
        let added1 = db.add_user(username, public_key, sender_tag).await.unwrap();
        assert!(added1);
        
        let result = db.add_user(username, "different_key", "different_tag").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_user_field() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let username = "test_user";
        let public_key = "test_public_key";
        let sender_tag = "test_sender_tag";
        
        db.add_user(username, public_key, sender_tag).await.unwrap();
        
        let updated = db.update_user_field(username, "senderTag", "new_sender_tag").await.unwrap();
        assert!(updated);
        
        let user = db.get_user_by_username(username).await.unwrap().unwrap();
        assert_eq!(user.2, "new_sender_tag");
    }

    #[tokio::test]
    async fn test_update_nonexistent_user() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let updated = db.update_user_field("nonexistent_user", "senderTag", "new_tag").await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn test_update_public_key() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();
        
        let username = "test_user";
        let public_key = "test_public_key";
        let sender_tag = "test_sender_tag";
        
        db.add_user(username, public_key, sender_tag).await.unwrap();
        
        let updated = db.update_user_field(username, "publicKey", "new_public_key").await.unwrap();
        assert!(updated);
        
        let user = db.get_user_by_username(username).await.unwrap().unwrap();
        assert_eq!(user.1, "new_public_key");
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();

        db.add_user("user1", "key1", "tag1").await.unwrap();
        db.add_user("user2", "key2", "tag2").await.unwrap();
        db.add_user("user3", "key3", "tag3").await.unwrap();

        let user1 = db.get_user_by_username("user1").await.unwrap().unwrap();
        let user2 = db.get_user_by_username("user2").await.unwrap().unwrap();
        let user3 = db.get_user_by_username("user3").await.unwrap().unwrap();

        assert_eq!(user1.0, "user1");
        assert_eq!(user2.0, "user2");
        assert_eq!(user3.0, "user3");
    }

    #[tokio::test]
    async fn test_update_user_field_rejects_invalid_field() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = DbUtils::new(db_path.to_str().unwrap()).await.unwrap();

        let username = "test_user";
        db.add_user(username, "test_key", "test_tag").await.unwrap();

        // SQL injection attempt should be rejected
        let result = db.update_user_field(username, "senderTag = 'injected'; DROP TABLE users; --", "value").await;
        assert!(result.is_err());

        // Invalid field names should be rejected
        let result = db.update_user_field(username, "invalidField", "value").await;
        assert!(result.is_err());

        // username field should not be updatable (it's the primary key)
        let result = db.update_user_field(username, "username", "new_username").await;
        assert!(result.is_err());

        // Valid fields should still work
        let result = db.update_user_field(username, "publicKey", "new_key").await;
        assert!(result.is_ok());

        let result = db.update_user_field(username, "senderTag", "new_tag").await;
        assert!(result.is_ok());
    }
}
