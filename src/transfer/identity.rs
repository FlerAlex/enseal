use anyhow::{Context, Result};
use magic_wormhole::{MailboxConnection, Wormhole};

use crate::crypto::envelope::Envelope;
use crate::crypto::signing::SignedEnvelope;
use crate::keys::identity::{EnsealIdentity, TrustedKey};

/// Create a mailbox for identity-mode wormhole transfer.
/// Returns the share code and signed wire bytes ready to send.
/// The code is available immediately so it can be displayed before the receiver connects.
pub async fn create_mailbox(
    envelope: &Envelope,
    recipients: &[&age::x25519::Recipient],
    sender: &EnsealIdentity,
    relay_url: Option<&str>,
    code_words: usize,
) -> Result<(String, Vec<u8>, MailboxConnection<serde_json::Value>)> {
    let inner_bytes = envelope.to_bytes()?;

    // Encrypt + sign
    let signed = SignedEnvelope::seal(&inner_bytes, recipients, sender)?;
    let wire_bytes = signed.to_bytes()?;

    let config = super::app_config(relay_url);

    tracing::debug!("connecting to rendezvous server (identity mode)...");
    let mailbox = MailboxConnection::create(config, code_words)
        .await
        .context("failed to connect to rendezvous server")?;

    let code = mailbox.code().to_string();

    Ok((code, wire_bytes, mailbox))
}

/// Send signed wire bytes through an already-created identity-mode mailbox.
pub async fn send(
    wire_bytes: Vec<u8>,
    mailbox: MailboxConnection<serde_json::Value>,
) -> Result<()> {
    let mut wormhole = Wormhole::connect(mailbox)
        .await
        .context("failed to establish wormhole connection")?;

    tracing::debug!("sending {} bytes (identity mode)...", wire_bytes.len());
    wormhole
        .send(wire_bytes)
        .await
        .context("failed to send data through wormhole")?;

    wormhole
        .close()
        .await
        .context("failed to close wormhole cleanly")?;

    Ok(())
}

/// Receive an identity-mode envelope via wormhole relay.
/// Verifies signature and decrypts with own age key.
#[allow(dead_code)]
pub async fn receive(
    code: &str,
    own_identity: &EnsealIdentity,
    expected_sender: Option<&TrustedKey>,
    relay_url: Option<&str>,
) -> Result<(Envelope, String)> {
    let config = super::app_config(relay_url);

    let code_parsed = code.parse().context("invalid wormhole code format")?;

    tracing::debug!("connecting to rendezvous server (identity mode)...");
    let mailbox = MailboxConnection::connect(config, code_parsed, true)
        .await
        .context("failed to connect to rendezvous server")?;

    let mut wormhole = Wormhole::connect(mailbox)
        .await
        .context("failed to establish wormhole connection")?;

    const MAX_WORMHOLE_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MiB

    tracing::debug!("waiting for data (identity mode)...");
    let data = wormhole
        .receive()
        .await
        .context("failed to receive data through wormhole")?;

    if data.len() > MAX_WORMHOLE_PAYLOAD {
        anyhow::bail!(
            "wormhole payload too large ({} bytes, max {})",
            data.len(),
            MAX_WORMHOLE_PAYLOAD
        );
    }

    wormhole
        .close()
        .await
        .context("failed to close wormhole cleanly")?;

    // Parse signed envelope
    let signed = SignedEnvelope::from_bytes(&data)?;
    let sender_pubkey = signed.sender_sign_pubkey.clone();

    // Verify + decrypt
    let inner_bytes = signed.open(own_identity, expected_sender)?;
    let envelope = Envelope::from_bytes(&inner_bytes)?;
    envelope.check_age(300)?;

    Ok((envelope, sender_pubkey))
}
