use anyhow::Result;
use sqlx::{Row, SqlitePool};
use std::path::Path;

#[derive(Clone)]
pub struct DbUtils {
    pool: SqlitePool,
}

impl DbUtils {
    /// Open or create the SQLite database at the specified path.
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_url = format!("sqlite:{}?mode=rwc", db_path.as_ref().display());
        let pool = SqlitePool::connect(&db_url).await?;
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
                groupID    TEXT PRIMARY KEY,
                userList   TEXT NOT NULL
            );
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

    /// Update a single field of a user. Returns true on success.
    pub async fn update_user_field(
        &self,
        username: &str,
        field: &str,
        value: &str,
    ) -> Result<bool> {
        let sql = format!("UPDATE users SET {} = ? WHERE username = ?", field);
        let res = sqlx::query(&sql)
            .bind(value)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
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
}
