use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};

use super::store::KeyStore;

/// Validate that an alias name contains only safe characters.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("alias name cannot be empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!(
            "alias name '{}' contains invalid characters (use A-Z, a-z, 0-9, _, -)",
            name
        );
    }
    Ok(())
}

/// Resolve an alias to its identity, returning None if not found.
pub fn resolve(store: &KeyStore, name: &str) -> Result<Option<String>> {
    let aliases = load_aliases(store)?;
    Ok(aliases.get(name).cloned())
}

/// Add or update an alias mapping.
pub fn set(store: &KeyStore, alias: &str, identity: &str) -> Result<()> {
    validate_name(alias)?;
    crate::keys::store::validate_identity_name(identity)?;
    let mut aliases = load_aliases(store)?;
    aliases.insert(alias.to_string(), identity.to_string());
    save_aliases(store, &aliases)
}

/// Remove an alias. Returns true if it existed.
pub fn remove(store: &KeyStore, alias: &str) -> Result<bool> {
    let mut aliases = load_aliases(store)?;
    let existed = aliases.remove(alias).is_some();
    if existed {
        save_aliases(store, &aliases)?;
    }
    Ok(existed)
}

/// List all aliases as (alias, identity) pairs.
pub fn list(store: &KeyStore) -> Result<Vec<(String, String)>> {
    let aliases = load_aliases(store)?;
    Ok(aliases.into_iter().collect())
}

fn load_aliases(store: &KeyStore) -> Result<BTreeMap<String, String>> {
    let path = store.aliases_path();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let content = std::fs::read_to_string(&path).context("failed to read aliases.toml")?;
    let aliases: BTreeMap<String, String> =
        toml::from_str(&content).context("failed to parse aliases.toml")?;
    Ok(aliases)
}

fn save_aliases(store: &KeyStore, aliases: &BTreeMap<String, String>) -> Result<()> {
    store.ensure_dirs()?;
    let content = toml::to_string_pretty(aliases).context("failed to serialize aliases")?;
    std::fs::write(store.aliases_path(), content).context("failed to write aliases.toml")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store(dir: &TempDir) -> KeyStore {
        KeyStore::open_at(dir.path().to_path_buf())
    }

    #[test]
    fn alias_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        assert_eq!(resolve(&store, "alice").unwrap(), None);

        set(&store, "alice", "alice@example.com").unwrap();
        assert_eq!(
            resolve(&store, "alice").unwrap(),
            Some("alice@example.com".to_string())
        );

        let all = list(&store).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            all[0],
            ("alice".to_string(), "alice@example.com".to_string())
        );

        assert!(remove(&store, "alice").unwrap());
        assert_eq!(resolve(&store, "alice").unwrap(), None);
        assert!(!remove(&store, "alice").unwrap());
    }
}
