use std::path::Path;

use anyhow::{Context, Result};

use crate::crypto::envelope::Envelope;
use crate::crypto::signing::SignedEnvelope;
use crate::keys::identity::{EnsealIdentity, TrustedKey};

/// Write an encrypted file drop: encrypt to recipients, sign with sender key.
/// Produces `<output_dir>/<filename>.env.age`.
pub fn write(
    envelope: &Envelope,
    recipients: &[&age::x25519::Recipient],
    sender: &EnsealIdentity,
    output_dir: &Path,
    filename: &str,
) -> Result<std::path::PathBuf> {
    let inner_bytes = envelope.to_bytes()?;
    let signed = SignedEnvelope::seal(&inner_bytes, recipients, sender)?;
    let wire_bytes = signed.to_bytes()?;

    // Sanitize filename: strip path separators and '..' to prevent directory traversal
    let safe_filename = filename.replace(['/', '\\'], "_").replace("..", "_");
    let dest = output_dir.join(format!("{}.env.age", safe_filename));

    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "failed to create output directory: {}",
            output_dir.display()
        )
    })?;

    // Write with restrictive permissions atomically (no TOCTOU window)
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
            .open(&dest)
            .with_context(|| format!("failed to write file: {}", dest.display()))?;
        file.write_all(&wire_bytes)
            .with_context(|| format!("failed to write file: {}", dest.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&dest, &wire_bytes)
            .with_context(|| format!("failed to write file: {}", dest.display()))?;
    }

    Ok(dest)
}

/// Read and decrypt a file drop.
pub fn read(
    path: &Path,
    own_identity: &EnsealIdentity,
    expected_sender: Option<&TrustedKey>,
) -> Result<(Envelope, String)> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read file: {}", path.display()))?;
    if metadata.len() > 16 * 1024 * 1024 {
        anyhow::bail!(
            "file too large ({} bytes, max 16 MiB): {}",
            metadata.len(),
            path.display()
        );
    }
    let data =
        std::fs::read(path).with_context(|| format!("failed to read file: {}", path.display()))?;
    read_from_bytes(&data, own_identity, expected_sender)
}

/// Read and decrypt a file drop from already-loaded bytes.
/// Use this to avoid reading the file twice (TOCTOU).
pub fn read_from_bytes(
    data: &[u8],
    own_identity: &EnsealIdentity,
    expected_sender: Option<&TrustedKey>,
) -> Result<(Envelope, String)> {
    let signed = SignedEnvelope::from_bytes(data)?;
    let sender_pubkey = signed.sender_sign_pubkey.clone();

    let inner_bytes = signed.open(own_identity, expected_sender)?;
    let envelope = Envelope::from_bytes(&inner_bytes)?;
    // Use a generous max age for file drops since files may sit on disk longer
    envelope.check_age(86400)?;

    Ok((envelope, sender_pubkey))
}
