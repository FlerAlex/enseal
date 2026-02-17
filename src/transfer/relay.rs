use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

/// Send bytes through an enseal relay server.
/// Returns the channel code that the receiver needs.
pub async fn send(data: &[u8], relay_url: &str, code: &str) -> Result<()> {
    let ws_url = format!("{}/channel/{}", normalize_ws_url(relay_url), code);

    tracing::debug!("connecting to enseal relay: {}", ws_url);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("failed to connect to enseal relay")?;

    // Send the data as a binary message
    ws.send(tungstenite::Message::Binary(data.to_vec()))
        .await
        .context("failed to send data through relay")?;

    // Wait for acknowledgment (the receiver reading the message)
    // or the connection closing
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(tungstenite::Message::Close(_)) => break,
            Ok(tungstenite::Message::Binary(_)) => {
                // Got an ack or response, we're done
                break;
            }
            Err(_) => break,
            _ => continue,
        }
    }

    let _ = ws.close(None).await;
    Ok(())
}

/// Receive bytes from an enseal relay server using the given code.
pub async fn receive(relay_url: &str, code: &str) -> Result<Vec<u8>> {
    let ws_url = format!("{}/channel/{}", normalize_ws_url(relay_url), code);

    tracing::debug!("connecting to enseal relay: {}", ws_url);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("failed to connect to enseal relay")?;

    // Wait for a binary message from the sender
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(tungstenite::Message::Binary(data)) => {
                // Send ack
                let _ = ws.send(tungstenite::Message::Binary(b"ack".to_vec())).await;
                let _ = ws.close(None).await;
                return Ok(data.to_vec());
            }
            Ok(tungstenite::Message::Close(_)) => {
                anyhow::bail!("relay closed connection before data was received");
            }
            Err(e) => {
                anyhow::bail!("relay connection error: {}", e);
            }
            _ => continue,
        }
    }

    anyhow::bail!("relay connection ended without receiving data")
}

/// Push data to a relay channel (identity mode sender).
/// The channel_id is derived from the recipient's identity.
pub async fn push(data: &[u8], relay_url: &str, channel_id: &str) -> Result<()> {
    send(data, relay_url, channel_id).await
}

/// Listen on a relay channel for incoming data (identity mode receiver).
/// The channel_id is derived from own identity.
pub async fn listen(relay_url: &str, channel_id: &str) -> Result<Vec<u8>> {
    receive(relay_url, channel_id).await
}

/// Generate a short channel code for relay transport.
pub fn generate_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let num: u32 = rng.gen_range(1000..9999);
    // Use a simple word list for human-friendly codes
    let words = [
        "alpha", "bravo", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo",
        "lima", "mike", "nova", "oscar", "papa", "romeo", "sierra", "tango", "ultra", "victor",
        "whiskey", "xray", "yankee", "zulu", "amber", "bronze", "coral", "dusk", "ember", "frost",
        "glacier", "harbor", "ivory", "jade", "karma", "lemon", "marble", "nectar", "opal",
        "prism", "quartz", "ruby", "sage", "topaz", "umbra", "velvet", "willow", "zenith",
    ];
    let w1 = words[rng.gen_range(0..words.len())];
    let w2 = words[rng.gen_range(0..words.len())];
    format!("{}-{}-{}", num, w1, w2)
}

/// Normalize relay URL to WebSocket format.
/// Converts http(s) to ws(s) and strips trailing slashes.
fn normalize_ws_url(url: &str) -> String {
    let url = url.trim_end_matches('/');
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        tracing::warn!("upgrading insecure http:// relay URL to wss://");
        format!("wss://{rest}")
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        url.to_string()
    } else {
        format!("wss://{}", url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_urls() {
        assert_eq!(
            normalize_ws_url("http://localhost:4443"),
            "wss://localhost:4443"
        );
        assert_eq!(
            normalize_ws_url("https://relay.example.com"),
            "wss://relay.example.com"
        );
        assert_eq!(normalize_ws_url("ws://relay:4443/"), "ws://relay:4443");
        assert_eq!(
            normalize_ws_url("wss://relay.internal"),
            "wss://relay.internal"
        );
        assert_eq!(
            normalize_ws_url("relay.example.com:4443"),
            "wss://relay.example.com:4443"
        );
    }

    #[test]
    fn code_generation() {
        let code = generate_code();
        assert!(code.contains('-'));
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);
        // First part is a number
        assert!(parts[0].parse::<u32>().is_ok());
    }
}
