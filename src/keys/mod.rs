pub mod alias;
pub mod group;
pub mod identity;
pub mod store;

use anyhow::{bail, Result};

/// Resolve a recipient name to one or more identities.
/// Checks: alias -> group -> trusted key -> error.
/// Returns a Vec with 1 element for a single identity, N for a group.
pub fn resolve_to_identities(name: &str) -> Result<Vec<String>> {
    let store = store::KeyStore::open()?;

    // Try alias first
    if let Some(identity) = alias::resolve(&store, name)? {
        return Ok(vec![identity]);
    }

    // Try group
    if let Some(members) = group::get_members(&store, name)? {
        if members.is_empty() {
            bail!("group '{}' has no members", name);
        }
        return Ok(members);
    }

    // Try trusted key
    if store.trusted_key_path(name).exists() {
        return Ok(vec![name.to_string()]);
    }

    bail!(
        "unknown recipient '{}'. Import their key with: enseal keys import <file>\n\
         Or create an alias with: enseal keys alias {} <identity>\n\
         Or create a group with: enseal keys group create {}",
        name,
        name,
        name
    );
}
