pub mod alias;
pub mod group;
pub mod identity;
pub mod store;

use anyhow::{bail, Result};

use crate::crypto::signing::SignedEnvelope;

/// Resolve a recipient name to one or more identities.
/// Checks: alias -> group -> trusted key -> error.
/// Returns a Vec with 1 element for a single identity, N for a group.
pub fn resolve_to_identities(name: &str) -> Result<Vec<String>> {
    store::validate_identity_name(name)?;
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
    if store.trusted_key_path(name)?.exists() {
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

/// Look up the sender's signing key in the trusted key store.
/// Returns the matching TrustedKey if found, None otherwise.
pub fn find_trusted_sender(
    store: &store::KeyStore,
    signed: &SignedEnvelope,
) -> Option<identity::TrustedKey> {
    let trusted = store.list_trusted().ok()?;
    for name in &trusted {
        if let Ok(key) = identity::TrustedKey::load(store, name) {
            let key_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                key.verifying_key.to_bytes(),
            );
            if key_b64 == signed.sender_sign_pubkey {
                return Some(key);
            }
        }
    }
    None
}
