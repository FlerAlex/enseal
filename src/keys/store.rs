use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use directories::ProjectDirs;

/// Validate that an identity name is safe for use in file paths.
/// Rejects path separators, `..` components, and null bytes.
pub fn validate_identity_name(identity: &str) -> Result<()> {
    if identity.is_empty() {
        bail!("identity name cannot be empty");
    }
    if identity.contains('/') || identity.contains('\\') {
        bail!(
            "identity name '{}' contains path separators, which is not allowed",
            identity
        );
    }
    if identity.contains("..") {
        bail!(
            "identity name '{}' contains '..', which is not allowed",
            identity
        );
    }
    if identity.contains('\0') {
        bail!("identity name contains null bytes, which is not allowed");
    }
    if identity.starts_with('.') {
        bail!("identity name '{}' cannot start with a dot", identity);
    }
    if identity.chars().any(|c| c.is_ascii_control() || c == ' ') {
        bail!(
            "identity name '{}' contains whitespace or control characters, which is not allowed",
            identity
        );
    }
    Ok(())
}

/// Manages the `~/.config/enseal/keys/` directory and file layout.
pub struct KeyStore {
    base_dir: PathBuf,
}

impl KeyStore {
    /// Open the key store at the default platform config directory.
    pub fn open() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "enseal", "enseal")
            .context("could not determine config directory")?;
        let base_dir = dirs.config_dir().to_path_buf();
        Ok(Self { base_dir })
    }

    /// Open the key store at a specific directory (for testing).
    pub fn open_at(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Ensure the key store directory structure exists.
    pub fn ensure_dirs(&self) -> Result<()> {
        let keys_dir = self.keys_dir();
        let trusted_dir = self.trusted_dir();
        std::fs::create_dir_all(&keys_dir)
            .with_context(|| format!("failed to create {}", keys_dir.display()))?;
        std::fs::create_dir_all(&trusted_dir)
            .with_context(|| format!("failed to create {}", trusted_dir.display()))?;
        Ok(())
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.base_dir.join("keys")
    }

    pub fn trusted_dir(&self) -> PathBuf {
        self.base_dir.join("keys").join("trusted")
    }

    // --- Own key paths ---

    pub fn age_private_key_path(&self) -> PathBuf {
        self.keys_dir().join("self.age.key")
    }

    pub fn age_public_key_path(&self) -> PathBuf {
        self.keys_dir().join("self.age.pub")
    }

    pub fn sign_private_key_path(&self) -> PathBuf {
        self.keys_dir().join("self.sign.key")
    }

    pub fn sign_public_key_path(&self) -> PathBuf {
        self.keys_dir().join("self.sign.pub")
    }

    // --- Trusted key paths ---

    /// Get the path for a trusted key file, validating the identity name.
    /// Returns an error if the identity name contains path traversal characters.
    pub fn trusted_key_path(&self, identity: &str) -> Result<PathBuf> {
        validate_identity_name(identity)?;
        Ok(self.trusted_dir().join(format!("{}.pub", identity)))
    }

    // --- Config file paths ---

    pub fn aliases_path(&self) -> PathBuf {
        self.base_dir.join("aliases.toml")
    }

    pub fn groups_path(&self) -> PathBuf {
        self.base_dir.join("groups.toml")
    }

    /// Check whether own keys have been initialized (all four key files present).
    pub fn is_initialized(&self) -> bool {
        self.age_private_key_path().exists()
            && self.sign_private_key_path().exists()
            && self.age_public_key_path().exists()
            && self.sign_public_key_path().exists()
    }

    /// List all trusted identities (by filename stem).
    pub fn list_trusted(&self) -> Result<Vec<String>> {
        let trusted_dir = self.trusted_dir();
        if !trusted_dir.exists() {
            return Ok(Vec::new());
        }
        let mut identities = Vec::new();
        for entry in std::fs::read_dir(&trusted_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Skip entries with invalid identity names (e.g. path traversal)
                    if validate_identity_name(stem).is_ok() {
                        identities.push(stem.to_string());
                    }
                }
            }
        }
        identities.sort();
        Ok(identities)
    }

    /// Write a file with restrictive permissions (0600) for private keys.
    /// On Unix, the file is created with 0600 mode atomically to avoid a
    /// window where the file is world-readable.
    pub fn write_private(&self, path: &Path, content: &str) -> Result<()> {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(content.as_bytes())?;
            // Ensure 0600 even if the file already existed with wrong permissions
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, content)?;
        }
        Ok(())
    }
}
