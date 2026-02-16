pub mod alias;
pub mod identity;
pub mod store;

use anyhow::{bail, Result};

/// Resolve a recipient string: try alias first, then treat as literal identity.
pub fn resolve_recipient(name: &str) -> Result<String> {
    let store = store::KeyStore::open()?;

    // Try alias
    if let Some(identity) = alias::resolve(&store, name)? {
        return Ok(identity);
    }

    // Check if it's a known identity in trusted keys
    if store.trusted_key_path(name).exists() {
        return Ok(name.to_string());
    }

    bail!(
        "unknown recipient '{}'. Import their key with: enseal keys import <file>\n\
         Or create an alias with: enseal keys alias {} <identity>",
        name,
        name
    );
}
