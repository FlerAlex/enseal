use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::store::KeyStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEntry {
    pub members: Vec<String>,
}

/// Validate that a group name contains only safe characters.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("group name cannot be empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!(
            "group name '{}' contains invalid characters (use A-Z, a-z, 0-9, _, -)",
            name
        );
    }
    Ok(())
}

/// Create a new group. Errors if it already exists.
pub fn create(store: &KeyStore, name: &str) -> Result<()> {
    validate_name(name)?;
    let mut groups = load_groups(store)?;
    if groups.contains_key(name) {
        bail!("group '{}' already exists", name);
    }
    groups.insert(
        name.to_string(),
        GroupEntry {
            members: Vec::new(),
        },
    );
    save_groups(store, &groups)
}

/// Add a member to a group. Errors if the group doesn't exist. Skips if already a member.
pub fn add_member(store: &KeyStore, group: &str, identity: &str) -> Result<bool> {
    crate::keys::store::validate_identity_name(identity)?;
    let mut groups = load_groups(store)?;
    let entry = groups
        .get_mut(group)
        .ok_or_else(|| anyhow::anyhow!("group '{}' does not exist", group))?;

    if entry.members.contains(&identity.to_string()) {
        return Ok(false);
    }

    entry.members.push(identity.to_string());
    save_groups(store, &groups)?;
    Ok(true)
}

/// Remove a member from a group. Returns whether the member was found.
pub fn remove_member(store: &KeyStore, group: &str, identity: &str) -> Result<bool> {
    let mut groups = load_groups(store)?;
    let entry = groups
        .get_mut(group)
        .ok_or_else(|| anyhow::anyhow!("group '{}' does not exist", group))?;

    let len_before = entry.members.len();
    entry.members.retain(|m| m != identity);
    let removed = entry.members.len() < len_before;

    if removed {
        save_groups(store, &groups)?;
    }
    Ok(removed)
}

/// Delete a group entirely. Returns whether it existed.
pub fn delete_group(store: &KeyStore, name: &str) -> Result<bool> {
    let mut groups = load_groups(store)?;
    let existed = groups.remove(name).is_some();
    if existed {
        save_groups(store, &groups)?;
    }
    Ok(existed)
}

/// Get members of a group. Returns None if the group doesn't exist.
pub fn get_members(store: &KeyStore, name: &str) -> Result<Option<Vec<String>>> {
    let groups = load_groups(store)?;
    Ok(groups.get(name).map(|e| e.members.clone()))
}

/// List all groups as (name, entry) pairs.
pub fn list_groups(store: &KeyStore) -> Result<Vec<(String, GroupEntry)>> {
    let groups = load_groups(store)?;
    Ok(groups.into_iter().collect())
}

fn load_groups(store: &KeyStore) -> Result<BTreeMap<String, GroupEntry>> {
    let path = store.groups_path();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let content = std::fs::read_to_string(&path).context("failed to read groups.toml")?;
    let groups: BTreeMap<String, GroupEntry> =
        toml::from_str(&content).context("failed to parse groups.toml")?;
    Ok(groups)
}

fn save_groups(store: &KeyStore, groups: &BTreeMap<String, GroupEntry>) -> Result<()> {
    store.ensure_dirs()?;
    let content = toml::to_string_pretty(groups).context("failed to serialize groups")?;
    std::fs::write(store.groups_path(), content).context("failed to write groups.toml")?;
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
    fn create_and_list() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        create(&store, "backend").unwrap();
        let groups = list_groups(&store).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "backend");
        assert!(groups[0].1.members.is_empty());
    }

    #[test]
    fn create_duplicate_errors() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        create(&store, "team").unwrap();
        let err = create(&store, "team").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_and_remove_members() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        create(&store, "devops").unwrap();

        assert!(add_member(&store, "devops", "alice@example.com").unwrap());
        assert!(add_member(&store, "devops", "bob@example.com").unwrap());

        // Duplicate add returns false
        assert!(!add_member(&store, "devops", "alice@example.com").unwrap());

        let members = get_members(&store, "devops").unwrap().unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"alice@example.com".to_string()));
        assert!(members.contains(&"bob@example.com".to_string()));

        // Remove
        assert!(remove_member(&store, "devops", "alice@example.com").unwrap());
        assert!(!remove_member(&store, "devops", "alice@example.com").unwrap());

        let members = get_members(&store, "devops").unwrap().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], "bob@example.com");
    }

    #[test]
    fn add_to_nonexistent_errors() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        let err = add_member(&store, "nope", "alice@example.com").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn delete_group() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        create(&store, "temp").unwrap();
        assert!(super::delete_group(&store, "temp").unwrap());
        assert!(!super::delete_group(&store, "temp").unwrap());
        assert!(get_members(&store, "temp").unwrap().is_none());
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);

        assert!(get_members(&store, "nope").unwrap().is_none());
    }
}
