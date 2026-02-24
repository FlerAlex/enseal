use anyhow::{bail, Context, Result};
use magic_wormhole::{MailboxConnection, Wormhole};

use crate::crypto::envelope::Envelope;

/// Maximum payload size accepted via wormhole (16 MiB).
const MAX_WORMHOLE_PAYLOAD: usize = 16 * 1024 * 1024;

/// Create a wormhole mailbox and return the share code and mailbox.
/// The code is available immediately, before the receiver connects.
pub async fn create_mailbox(
    relay_url: Option<&str>,
    code_words: usize,
) -> Result<(String, MailboxConnection<serde_json::Value>)> {
    let config = super::app_config(relay_url);

    tracing::debug!("connecting to rendezvous server...");
    let mailbox = MailboxConnection::create(config, code_words)
        .await
        .context("failed to connect to rendezvous server")?;

    let code = mailbox.code().to_string();
    Ok((code, mailbox))
}

/// Send an envelope through an already-created mailbox.
pub async fn send(
    envelope: &Envelope,
    mailbox: MailboxConnection<serde_json::Value>,
) -> Result<()> {
    let mut wormhole = Wormhole::connect(mailbox)
        .await
        .context("failed to establish wormhole connection")?;

    let data = envelope.to_bytes()?;

    tracing::debug!("sending {} bytes...", data.len());
    wormhole
        .send(data)
        .await
        .context("failed to send data through wormhole")?;

    wormhole
        .close()
        .await
        .context("failed to close wormhole cleanly")?;

    Ok(())
}

/// Receive raw bytes via magic-wormhole using the given code.
/// Returns the raw data without attempting to parse it.
pub async fn receive_raw(code: &str, relay_url: Option<&str>) -> Result<Vec<u8>> {
    let config = super::app_config(relay_url);

    let code = code.parse().context("invalid wormhole code format")?;

    tracing::debug!("connecting to rendezvous server...");
    let mailbox = MailboxConnection::connect(config, code, true)
        .await
        .context("failed to connect to rendezvous server")?;

    let mut wormhole = Wormhole::connect(mailbox)
        .await
        .context("failed to establish wormhole connection")?;

    // NOTE: magic-wormhole allocates the full payload before returning.
    // This size check is defense-in-depth but cannot prevent OOM from a
    // malicious sender. The wormhole protocol and rendezvous server impose
    // their own practical limits, and the sender must complete the SPAKE2
    // handshake with the correct code first.
    tracing::debug!("waiting for data...");
    let data = wormhole
        .receive()
        .await
        .context("failed to receive data through wormhole")?;

    if data.len() > MAX_WORMHOLE_PAYLOAD {
        bail!(
            "payload too large ({} bytes, max {})",
            data.len(),
            MAX_WORMHOLE_PAYLOAD
        );
    }

    wormhole
        .close()
        .await
        .context("failed to close wormhole cleanly")?;

    Ok(data)
}

/// Receive an envelope via magic-wormhole using the given code.
pub async fn receive(code: &str, relay_url: Option<&str>) -> Result<Envelope> {
    let data = receive_raw(code, relay_url).await?;
    let envelope = Envelope::from_bytes(&data)?;
    envelope.check_age(300)?;
    Ok(envelope)
}
