use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;

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

    pub fn trusted_key_path(&self, identity: &str) -> PathBuf {
        self.trusted_dir().join(format!("{}.pub", identity))
    }

    // --- Config file paths ---

    pub fn aliases_path(&self) -> PathBuf {
        self.base_dir.join("aliases.toml")
    }

    pub fn groups_path(&self) -> PathBuf {
        self.base_dir.join("groups.toml")
    }

    /// Check whether own keys have been initialized.
    pub fn is_initialized(&self) -> bool {
        self.age_private_key_path().exists() && self.sign_private_key_path().exists()
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
                    identities.push(stem.to_string());
                }
            }
        }
        identities.sort();
        Ok(identities)
    }

    /// Write a file with restrictive permissions (0600) for private keys.
    pub fn write_private(&self, path: &Path, content: &str) -> Result<()> {
        std::fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
