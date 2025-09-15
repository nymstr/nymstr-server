use dotenvy::dotenv;

/// Load environment variables from a .env file.
pub fn load_env() {
    // Load .env file, ignore errors if file not found.
    dotenv().ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_load_env_no_file() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        
        let _ = env::set_current_dir(temp_dir.path());
        
        load_env();
        
        let _ = env::set_current_dir(original_dir);
    }

    #[test]
    fn test_load_env_with_file() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        
        let env_file = temp_dir.path().join(".env");
        fs::write(&env_file, "TEST_VAR=test_value\nANOTHER_VAR=another_value").unwrap();
        
        let _ = env::set_current_dir(temp_dir.path());
        
        load_env();
        
        assert_eq!(env::var("TEST_VAR").unwrap(), "test_value");
        assert_eq!(env::var("ANOTHER_VAR").unwrap(), "another_value");
        
        let _ = env::set_current_dir(original_dir);
        
        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("ANOTHER_VAR");
        }
    }

    #[test]
    fn test_load_env_empty_file() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        
        let env_file = temp_dir.path().join(".env");
        fs::write(&env_file, "").unwrap();
        
        let _ = env::set_current_dir(temp_dir.path());
        
        load_env();
        
        let _ = env::set_current_dir(original_dir);
    }

    #[test]
    fn test_load_env_invalid_format() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        
        let env_file = temp_dir.path().join(".env");
        fs::write(&env_file, "INVALID_LINE_WITHOUT_EQUALS\nVALID_VAR=valid_value").unwrap();
        
        let _ = env::set_current_dir(temp_dir.path());
        
        load_env();
        
        if let Ok(val) = env::var("VALID_VAR") {
            assert_eq!(val, "valid_value");
        }
        
        let _ = env::set_current_dir(original_dir);
        
        unsafe {
            env::remove_var("VALID_VAR");
        }
    }

    #[test]
    fn test_load_env_comments_and_empty_lines() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        
        let env_file = temp_dir.path().join(".env");
        fs::write(&env_file, "# This is a comment\nTEST_VAR=test_value\n\n# Another comment\nANOTHER_VAR=another_value").unwrap();
        
        let _ = env::set_current_dir(temp_dir.path());
        
        load_env();
        
        assert_eq!(env::var("TEST_VAR").unwrap(), "test_value");
        assert_eq!(env::var("ANOTHER_VAR").unwrap(), "another_value");
        
        let _ = env::set_current_dir(original_dir);
        
        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("ANOTHER_VAR");
        }
    }
}
