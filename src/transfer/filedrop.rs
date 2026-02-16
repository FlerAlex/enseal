use std::path::Path;

use anyhow::{Context, Result};

use crate::crypto::envelope::Envelope;
use crate::crypto::signing::SignedEnvelope;
use crate::keys::identity::{EnsealIdentity, TrustedKey};

/// Write an encrypted file drop: encrypt to recipient, sign with sender key.
/// Produces `<output_dir>/<identity>.env.age`.
pub fn write(
    envelope: &Envelope,
    recipient: &TrustedKey,
    sender: &EnsealIdentity,
    output_dir: &Path,
) -> Result<std::path::PathBuf> {
    let inner_bytes = envelope.to_bytes()?;
    let signed = SignedEnvelope::seal(&inner_bytes, &recipient.age_recipient, sender)?;
    let wire_bytes = signed.to_bytes()?;

    let filename = format!("{}.env.age", recipient.identity);
    let dest = output_dir.join(&filename);

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory: {}", output_dir.display()))?;

    std::fs::write(&dest, &wire_bytes)
        .with_context(|| format!("failed to write file: {}", dest.display()))?;

    Ok(dest)
}

/// Read and decrypt a file drop.
pub fn read(
    path: &Path,
    own_identity: &EnsealIdentity,
    expected_sender: Option<&TrustedKey>,
) -> Result<(Envelope, String)> {
    let data =
        std::fs::read(path).with_context(|| format!("failed to read file: {}", path.display()))?;

    let signed = SignedEnvelope::from_bytes(&data)?;
    let sender_pubkey = signed.sender_age_pubkey.clone();

    let inner_bytes = signed.open(own_identity, expected_sender)?;
    let envelope = Envelope::from_bytes(&inner_bytes)?;

    Ok((envelope, sender_pubkey))
}
