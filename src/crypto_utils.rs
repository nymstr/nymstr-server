use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use hex;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs;
use std::path::PathBuf;
use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey, SignedPublicKey, Deserializable, StandaloneSignature};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{Password, KeyDetails};
use pgp::ser::Serialize as PgpSerialize;
use rand::thread_rng;
use std::time::SystemTime;

/// Utility for key generation, encryption, signing, and verification.
pub struct CryptoUtils {
    key_dir: PathBuf,
    password: String,
}

impl CryptoUtils {
    /// Create a new CryptoUtils, ensuring the key directory exists.
    pub fn new(key_dir: PathBuf, password: String) -> Result<Self> {
        if !key_dir.exists() {
            fs::create_dir_all(&key_dir)?;
        }
        Ok(Self { key_dir, password })
    }

    fn derive_key(&self, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        pbkdf2_hmac(
            self.password.as_bytes(),
            salt,
            100_000,
            MessageDigest::sha256(),
            &mut key,
        )?;
        Ok(key)
    }

    fn encrypt_private_key(&self, private_key_pem: &[u8]) -> Result<String> {
        let mut salt = [0u8; 16];
        rand_bytes(&mut salt)?;
        let mut iv = [0u8; 12];
        rand_bytes(&mut iv)?;
        let key = self.derive_key(&salt)?;
        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
        let mut ciphertext = vec![0; private_key_pem.len() + cipher.block_size()];
        let mut count = crypter.update(private_key_pem, &mut ciphertext)?;
        count += crypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);
        let mut tag = [0u8; 16];
        crypter.get_tag(&mut tag)?;
        let mut data = Vec::new();
        data.extend_from_slice(&salt);
        data.extend_from_slice(&iv);
        data.extend_from_slice(&tag);
        data.extend_from_slice(&ciphertext);
        Ok(general_purpose::STANDARD.encode(data))
    }

    fn decrypt_private_key(&self, encrypted_data: &str) -> Result<Vec<u8>> {
        let data = general_purpose::STANDARD.decode(encrypted_data)?;
        let (salt, rest) = data.split_at(16);
        let (iv, rest) = rest.split_at(12);
        let (tag, ciphertext) = rest.split_at(16);
        let key = self.derive_key(salt)?;
        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(iv))?;
        crypter.set_tag(tag)?;
        let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
        let mut count = crypter.update(ciphertext, &mut plaintext)?;
        count += crypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);
        Ok(plaintext)
    }

    /// Convert password to PGP Password type
    fn to_pgp_password(&self) -> Password {
        Password::from(self.password.as_str())
    }

    /// Generate and securely store a new PGP key pair using Ed25519.
    /// Returns the public key armored as a String.
    pub fn generate_key_pair(&self, username: &str) -> Result<String> {
        log::info!("Generating Ed25519 PGP keypair for user: {}", username);

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(username.to_string())
            .build()?;

        let secret_key = key_params.generate(thread_rng())?;
        let signed_secret_key = secret_key.sign(&mut thread_rng(), &self.to_pgp_password())?;
        let public_key = SignedPublicKey::from(signed_secret_key.clone());

        let secret_key_armored = signed_secret_key.to_armored_string(Default::default())?;
        let public_key_armored = public_key.to_armored_string(Default::default())?;

        let encrypted = self.encrypt_private_key(secret_key_armored.as_bytes())?;
        let priv_path = self.key_dir.join(format!("{}_private_key.enc", username));
        let pub_path = self.key_dir.join(format!("{}_public_key.asc", username));
        fs::write(priv_path, encrypted)?;
        fs::write(pub_path, &public_key_armored)?;
        log::info!("generateKeyPair - success!");
        Ok(public_key_armored)
    }

    /// Load and decrypt a private key for the given username.
    pub fn load_private_key(&self, username: &str) -> Result<SignedSecretKey> {
        let path = self.key_dir.join(format!("{}_private_key.enc", username));
        let encrypted = fs::read_to_string(path)?;
        let decrypted = self.decrypt_private_key(&encrypted)?;
        let armored_key = String::from_utf8(decrypted)?;
        let (secret_key, _headers) = SignedSecretKey::from_string(&armored_key)?;
        Ok(secret_key)
    }

    /// Load the public key for the given username.
    #[allow(dead_code)] // Part of public API for future use
    pub fn load_public_key(&self, username: &str) -> Result<SignedPublicKey> {
        let path = self.key_dir.join(format!("{}_public_key.asc", username));
        let armored = fs::read_to_string(&path)?;
        let (public_key, _headers) = SignedPublicKey::from_string(&armored)?;
        Ok(public_key)
    }

    /// Sign a message using the user's private key. Returns a base64-encoded signature.
    pub fn sign_message(&self, username: &str, message: &str) -> Result<String> {
        log::info!("Attempting to sign message for username: '{}' (length: {} bytes)", username, message.len());
        let secret_key = match self.load_private_key(username) {
            Ok(key) => {
                log::info!("Successfully loaded private key for username: '{}'", username);
                key
            }
            Err(e) => {
                log::error!("Failed to load private key for username '{}': {}", username, e);
                return Err(e);
            }
        };

        // Always hash the message before signing for consistent behavior
        log::info!("Hashing message ({} bytes) before signing", message.len());
        use openssl::sha::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finish();
        let message_to_sign = hex::encode(hash);

        // Create signature using SignatureConfig (pgp 0.16 API)
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Binary,
        )?;

        // Add required subpackets
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.primary_key.fingerprint(),
            ))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                SystemTime::now().into(),
            ))?,
        ];

        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(secret_key.primary_key.key_id()))?
        ];

        let signature = config.sign(
            &secret_key.primary_key,
            &self.to_pgp_password(),
            message_to_sign.as_bytes(),
        )?;

        // Wrap in StandaloneSignature and serialize
        let standalone = StandaloneSignature::new(signature);
        let signature_bytes = PgpSerialize::to_bytes(&standalone)?;

        log::info!("Successfully signed message for username: '{}'", username);
        Ok(general_purpose::STANDARD.encode(signature_bytes))
    }

    /// Verify an armored PGP signature against a public key armored string.
    pub fn verify_signature(
        &self,
        public_key_armored: &str,
        message: &str,
        signature_armored: &str,
    ) -> bool {
        match self.verify_signature_inner(public_key_armored, message, signature_armored) {
            Ok(valid) => valid,
            Err(e) => {
                log::error!("verifySignature - failed: {}", e);
                false
            }
        }
    }

    fn verify_signature_inner(
        &self,
        public_key_armored: &str,
        message: &str,
        signature_armored: &str,
    ) -> Result<bool> {
        // Parse the armored signature (not base64)
        let signature = if signature_armored.starts_with("-----BEGIN PGP SIGNATURE-----") {
            // It's an armored signature, parse it directly
            let (sig, _headers) = StandaloneSignature::from_string(signature_armored)?;
            sig
        } else {
            // Fall back to base64 decoding for backward compatibility
            let signature_bytes = general_purpose::STANDARD.decode(signature_armored)?;
            StandaloneSignature::from_bytes(signature_bytes.as_slice())?
        };

        let (public_key, _headers) = SignedPublicKey::from_string(public_key_armored)?;

        // Hash the message the same way as sign_message does
        use openssl::sha::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finish();
        let message_to_verify = hex::encode(hash);

        // Verify the signature against the hashed message
        match signature.verify(&public_key.primary_key, message_to_verify.as_bytes()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_creates_key_directory() {
        let temp_dir = tempdir().unwrap();
        let key_dir = temp_dir.path().join("keys");

        let _crypto = CryptoUtils::new(key_dir.clone(), "test_password".to_string()).unwrap();

        assert!(key_dir.exists());
    }

    #[test]
    fn test_derive_key_consistency() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let salt = [1u8; 16];
        let key1 = crypto.derive_key(&salt).unwrap();
        let key2 = crypto.derive_key(&salt).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_private_key() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let test_data = b"test private key data";
        let encrypted = crypto.encrypt_private_key(test_data).unwrap();
        let decrypted = crypto.decrypt_private_key(&encrypted).unwrap();

        assert_eq!(test_data, &decrypted[..]);
    }

    #[test]
    fn test_generate_key_pair() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let public_key = crypto.generate_key_pair("test_user").unwrap();

        assert!(!public_key.is_empty());
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));

        let private_key_path = temp_dir.path().join("test_user_private_key.enc");
        let public_key_path = temp_dir.path().join("test_user_public_key.asc");

        assert!(private_key_path.exists());
        assert!(public_key_path.exists());
    }

    #[test]
    fn test_load_keys_after_generation() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        crypto.generate_key_pair("test_user").unwrap();

        let secret_key = crypto.load_private_key("test_user").unwrap();
        let public_key = crypto.load_public_key("test_user").unwrap();

        assert!(!secret_key.to_armored_string(Default::default()).unwrap().is_empty());
        assert!(!public_key.to_armored_string(Default::default()).unwrap().is_empty());
    }

    #[test]
    fn test_sign_message() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        crypto.generate_key_pair("test_user").unwrap();

        let message = "test message to sign";
        let signature = crypto.sign_message("test_user", message).unwrap();

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_verify_signature() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let public_key = crypto.generate_key_pair("test_user").unwrap();
        let message = "test message to sign";
        let signature = crypto.sign_message("test_user", message).unwrap();

        let is_valid = crypto.verify_signature(&public_key, message, &signature);
        assert!(is_valid);
    }

    #[test]
    fn test_verify_signature_invalid_message() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let public_key = crypto.generate_key_pair("test_user").unwrap();
        let message = "test message to sign";
        let signature = crypto.sign_message("test_user", message).unwrap();

        let is_valid = crypto.verify_signature(&public_key, "different message", &signature);
        assert!(!is_valid);
    }

    #[test]
    fn test_verify_signature_invalid_public_key() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        crypto.generate_key_pair("test_user").unwrap();
        let other_public_key = crypto.generate_key_pair("other_user").unwrap();

        let message = "test message to sign";
        let signature = crypto.sign_message("test_user", message).unwrap();

        let is_valid = crypto.verify_signature(&other_public_key, message, &signature);
        assert!(!is_valid);
    }

    #[test]
    fn test_load_nonexistent_key() {
        let temp_dir = tempdir().unwrap();
        let crypto = CryptoUtils::new(temp_dir.path().to_path_buf(), "test_password".to_string()).unwrap();

        let result = crypto.load_private_key("nonexistent_user");
        assert!(result.is_err());
    }
}
