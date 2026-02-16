use std::path::Path;

use anyhow::Result;
use serde::Deserialize;

/// Project-level configuration from `.enseal.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Manifest {
    pub defaults: Defaults,
    pub filter: FilterConfig,
    pub metadata: MetadataConfig,
    pub schema: Option<crate::env::schema::Schema>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Defaults {
    pub relay: Option<String>,
    pub timeout: Option<u64>,
    pub words: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetadataConfig {
    pub project: Option<String>,
}

impl Manifest {
    /// Try to load `.enseal.toml` from the given directory or current dir.
    /// Returns default config if file doesn't exist.
    pub fn load(config_path: Option<&str>) -> Result<Self> {
        let path = if let Some(p) = config_path {
            std::path::PathBuf::from(p)
        } else {
            std::path::PathBuf::from(".enseal.toml")
        };

        if !path.exists() {
            return Ok(Self::default());
        }

        Self::from_file(&path)
    }

    fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let manifest: Manifest = toml::from_str(&content)?;
        Ok(manifest)
    }
}
