use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use age::secrecy::ExposeSecret;

use super::store::KeyStore;

/// A complete enseal identity: age keypair (encryption) + ed25519 keypair (signing).
pub struct EnsealIdentity {
    pub age_identity: age::x25519::Identity,
    pub age_recipient: age::x25519::Recipient,
    pub signing_key: SigningKey,
}

/// A trusted public key bundle: age recipient + ed25519 verifying key.
pub struct TrustedKey {
    pub identity: String,
    pub age_recipient: age::x25519::Recipient,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl EnsealIdentity {
    /// Generate a new keypair.
    pub fn generate() -> Self {
        let age_identity = age::x25519::Identity::generate();
        let age_recipient = age_identity.to_public();
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            age_identity,
            age_recipient,
            signing_key,
        }
    }

    /// Load own identity from the key store.
    pub fn load(store: &KeyStore) -> Result<Self> {
        if !store.is_initialized() {
            bail!("no identity found. Run `enseal keys init` first.");
        }

        let age_key_str = std::fs::read_to_string(store.age_private_key_path())
            .context("failed to read age private key")?;
        let age_identity: age::x25519::Identity = age_key_str
            .trim()
            .parse()
            .map_err(|e: &str| anyhow::anyhow!("{}", e))?;
        let age_recipient = age_identity.to_public();

        let sign_key_b64 = std::fs::read_to_string(store.sign_private_key_path())
            .context("failed to read signing private key")?;
        let sign_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(sign_key_b64.trim())
            .context("invalid base64 in signing private key")?;
        let sign_key_array: [u8; 32] = sign_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
        let signing_key = SigningKey::from_bytes(&sign_key_array);

        Ok(Self {
            age_identity,
            age_recipient,
            signing_key,
        })
    }

    /// Save this identity to the key store.
    pub fn save(&self, store: &KeyStore) -> Result<()> {
        store.ensure_dirs()?;

        // Age private key
        let age_sk_str = self.age_identity.to_string();
        store.write_private(&store.age_private_key_path(), age_sk_str.expose_secret())?;

        // Age public key
        std::fs::write(store.age_public_key_path(), self.age_recipient.to_string())?;

        // Ed25519 signing key (raw 32 bytes)
        store.write_private(
            &store.sign_private_key_path(),
            &base64::engine::general_purpose::STANDARD.encode(self.signing_key.to_bytes()),
        )?;

        // Ed25519 verifying key (raw 32 bytes)
        std::fs::write(
            store.sign_public_key_path(),
            base64::engine::general_purpose::STANDARD
                .encode(self.signing_key.verifying_key().to_bytes()),
        )?;

        Ok(())
    }

    /// Compute the fingerprint of the public keys (SHA256 of age pubkey + sign pubkey).
    pub fn fingerprint(&self) -> String {
        fingerprint_from_keys(
            &self.age_recipient.to_string(),
            &base64::engine::general_purpose::STANDARD
                .encode(self.signing_key.verifying_key().to_bytes()),
        )
    }

    /// Compute a URL-safe channel ID for relay listen mode.
    /// Hex-encoded SHA256 prefix of the public keys.
    pub fn channel_id(&self) -> String {
        channel_id_from_keys(
            &self.age_recipient.to_string(),
            &base64::engine::general_purpose::STANDARD
                .encode(self.signing_key.verifying_key().to_bytes()),
        )
    }
}

impl TrustedKey {
    /// Parse a `.pub` file containing an enseal public key bundle.
    ///
    /// Format:
    /// ```text
    /// # enseal public key for alice@example.com
    /// # fingerprint: SHA256:...
    /// age: age1...
    /// sign: ed25519:<base64>
    /// ```
    pub fn parse(identity: &str, content: &str) -> Result<Self> {
        let mut age_pubkey: Option<String> = None;
        let mut sign_pubkey: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("age: ") {
                age_pubkey = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("sign: ed25519:") {
                sign_pubkey = Some(rest.trim().to_string());
            }
        }

        let age_str = age_pubkey.context("missing 'age:' line in public key file")?;
        let sign_str = sign_pubkey.context("missing 'sign: ed25519:' line in public key file")?;

        let age_recipient: age::x25519::Recipient = age_str
            .parse()
            .map_err(|e: &str| anyhow::anyhow!("invalid age public key: {}", e))?;

        let sign_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sign_str)
            .context("invalid base64 in sign public key")?;
        let sign_array: [u8; 32] = sign_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid ed25519 public key length"))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&sign_array)
            .context("invalid ed25519 public key")?;

        Ok(Self {
            identity: identity.to_string(),
            age_recipient,
            verifying_key,
        })
    }

    /// Load a trusted key from the store by identity name.
    pub fn load(store: &KeyStore, identity: &str) -> Result<Self> {
        let path = store.trusted_key_path(identity)?;
        if !path.exists() {
            bail!(
                "no public key found for '{}'. Import with: enseal keys import <file>",
                identity
            );
        }
        let content = std::fs::read_to_string(&path)?;
        Self::parse(identity, &content)
    }

    /// Compute the fingerprint of this key.
    pub fn fingerprint(&self) -> String {
        fingerprint_from_keys(
            &self.age_recipient.to_string(),
            &base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes()),
        )
    }

    /// Compute a URL-safe channel ID for relay listen mode.
    /// Hex-encoded SHA256 prefix of the public keys.
    pub fn channel_id(&self) -> String {
        channel_id_from_keys(
            &self.age_recipient.to_string(),
            &base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes()),
        )
    }
}

/// Format a public key bundle for export as a `.pub` file.
pub fn format_pubkey_file(identity: &str, age_pubkey: &str, sign_pubkey_b64: &str) -> String {
    let fingerprint = fingerprint_from_keys(age_pubkey, sign_pubkey_b64);
    format!(
        "# enseal public key for {}\n# fingerprint: {}\nage: {}\nsign: ed25519:{}\n",
        identity, fingerprint, age_pubkey, sign_pubkey_b64
    )
}

/// Compute a URL-safe channel ID from public key strings.
/// Returns hex-encoded SHA256 prefix (first 16 bytes = 32 hex chars).
fn channel_id_from_keys(age_pubkey: &str, sign_pubkey_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(age_pubkey.as_bytes());
    hasher.update(sign_pubkey_b64.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..16])
}

/// Compute SHA256 fingerprint from age + sign public key strings.
fn fingerprint_from_keys(age_pubkey: &str, sign_pubkey_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(age_pubkey.as_bytes());
    hasher.update(sign_pubkey_b64.as_bytes());
    let hash = hasher.finalize();
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(&hash[..16])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_and_fingerprint() {
        let id = EnsealIdentity::generate();
        let fp = id.fingerprint();
        assert!(fp.starts_with("SHA256:"));
        assert!(fp.len() > 10);
    }

    #[test]
    fn pubkey_file_round_trip() {
        let id = EnsealIdentity::generate();
        let age_pub = id.age_recipient.to_string();
        let sign_pub = base64::engine::general_purpose::STANDARD
            .encode(id.signing_key.verifying_key().to_bytes());
        let content = format_pubkey_file("test@example.com", &age_pub, &sign_pub);

        let parsed = TrustedKey::parse("test@example.com", &content).unwrap();
        assert_eq!(parsed.identity, "test@example.com");
        assert_eq!(parsed.age_recipient.to_string(), age_pub);
        assert_eq!(
            parsed.verifying_key.to_bytes(),
            id.signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn fingerprints_match() {
        let id = EnsealIdentity::generate();
        let age_pub = id.age_recipient.to_string();
        let sign_pub = base64::engine::general_purpose::STANDARD
            .encode(id.signing_key.verifying_key().to_bytes());
        let content = format_pubkey_file("test@example.com", &age_pub, &sign_pub);
        let parsed = TrustedKey::parse("test@example.com", &content).unwrap();
        assert_eq!(id.fingerprint(), parsed.fingerprint());
    }

    #[test]
    fn channel_ids_match() {
        let id = EnsealIdentity::generate();
        let age_pub = id.age_recipient.to_string();
        let sign_pub = base64::engine::general_purpose::STANDARD
            .encode(id.signing_key.verifying_key().to_bytes());
        let content = format_pubkey_file("test@example.com", &age_pub, &sign_pub);
        let parsed = TrustedKey::parse("test@example.com", &content).unwrap();

        let own_channel = id.channel_id();
        let trusted_channel = parsed.channel_id();
        assert_eq!(own_channel, trusted_channel);
        // Channel ID should be 32 hex chars (16 bytes)
        assert_eq!(own_channel.len(), 32);
        assert!(own_channel.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = KeyStore::open_at(dir.path().to_path_buf());

        let id = EnsealIdentity::generate();
        id.save(&store).unwrap();

        assert!(store.is_initialized());

        let loaded = EnsealIdentity::load(&store).unwrap();
        assert_eq!(id.fingerprint(), loaded.fingerprint());
        assert_eq!(
            id.age_recipient.to_string(),
            loaded.age_recipient.to_string()
        );
        assert_eq!(
            id.signing_key.verifying_key().to_bytes(),
            loaded.signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn trusted_key_save_and_load() {
        let dir = TempDir::new().unwrap();
        let store = KeyStore::open_at(dir.path().to_path_buf());
        store.ensure_dirs().unwrap();

        let id = EnsealIdentity::generate();
        let age_pub = id.age_recipient.to_string();
        let sign_pub = base64::engine::general_purpose::STANDARD
            .encode(id.signing_key.verifying_key().to_bytes());
        let content = format_pubkey_file("alice@example.com", &age_pub, &sign_pub);

        // Write to trusted dir
        std::fs::write(
            store.trusted_key_path("alice@example.com").unwrap(),
            &content,
        )
        .unwrap();

        let loaded = TrustedKey::load(&store, "alice@example.com").unwrap();
        assert_eq!(loaded.identity, "alice@example.com");
        assert_eq!(loaded.age_recipient.to_string(), age_pub);
        assert_eq!(loaded.fingerprint(), id.fingerprint());
    }

    #[cfg(unix)]
    #[test]
    fn private_keys_have_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let store = KeyStore::open_at(dir.path().to_path_buf());

        let id = EnsealIdentity::generate();
        id.save(&store).unwrap();

        let age_perms = std::fs::metadata(store.age_private_key_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let sign_perms = std::fs::metadata(store.sign_private_key_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(age_perms, 0o600);
        assert_eq!(sign_perms, 0o600);
    }
}
