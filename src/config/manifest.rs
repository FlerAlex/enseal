use std::path::Path;

use anyhow::Result;
use serde::Deserialize;

/// Project-level configuration from `.enseal.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Manifest {
    pub defaults: Defaults,
    pub filter: FilterConfig,
    pub identity: IdentityConfig,
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
pub struct IdentityConfig {
    pub default_recipient: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MetadataConfig {
    pub project: Option<String>,
}

impl Manifest {
    /// Try to load `.enseal.toml` from the given path or current directory.
    /// Returns default config if the file doesn't exist.
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

    /// Resolve the project name: explicit [metadata] project, then Cargo.toml, then package.json.
    pub fn project_name(&self) -> Option<String> {
        if let Some(ref p) = self.metadata.project {
            return Some(p.clone());
        }
        if let Ok(content) = std::fs::read_to_string("Cargo.toml") {
            if let Ok(table) = content.parse::<toml::Value>() {
                if let Some(name) = table
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                {
                    return Some(name.to_string());
                }
            }
        }
        if let Ok(content) = std::fs::read_to_string("package.json") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(name) = json.get("name").and_then(|n| n.as_str()) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }
}
