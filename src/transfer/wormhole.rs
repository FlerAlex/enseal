use anyhow::{Context, Result};
use magic_wormhole::{MailboxConnection, Wormhole};

use crate::crypto::envelope::Envelope;

/// Send an envelope via magic-wormhole. Returns the share code.
pub async fn send(
    envelope: &Envelope,
    relay_url: Option<&str>,
    code_words: usize,
) -> Result<String> {
    let config = super::app_config(relay_url);

    tracing::debug!("connecting to rendezvous server...");
    let mailbox = MailboxConnection::create(config, code_words)
        .await
        .context("failed to connect to rendezvous server")?;

    let code = mailbox.code().to_string();

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

    Ok(code)
}

/// Receive an envelope via magic-wormhole using the given code.
pub async fn receive(code: &str, relay_url: Option<&str>) -> Result<Envelope> {
    let config = super::app_config(relay_url);

    let code = code
        .parse()
        .context("invalid wormhole code format")?;

    tracing::debug!("connecting to rendezvous server...");
    let mailbox = MailboxConnection::connect(config, code, true)
        .await
        .context("failed to connect to rendezvous server")?;

    let mut wormhole = Wormhole::connect(mailbox)
        .await
        .context("failed to establish wormhole connection")?;

    tracing::debug!("waiting for data...");
    let data = wormhole
        .receive()
        .await
        .context("failed to receive data through wormhole")?;

    wormhole
        .close()
        .await
        .context("failed to close wormhole cleanly")?;

    let envelope = Envelope::from_bytes(&data)?;
    Ok(envelope)
}
