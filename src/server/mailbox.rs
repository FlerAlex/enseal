use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// Shared relay state across all connections.
pub struct RelayState {
    channels: Mutex<HashMap<String, Channel>>,
    max_channels: usize,
    channel_ttl_secs: u64,
    connection_log: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    rate_limit_per_min: usize,
    max_payload_bytes: usize,
}

struct Channel {
    /// Sender used to deliver messages TO the first client (live relay mode).
    to_first: mpsc::Sender<Message>,
    /// Receiver for messages FROM the first client (live relay mode).
    from_first: Option<mpsc::Receiver<Message>>,
    created_at: Instant,
    /// Stored payload for store-and-forward (sender pushed and disconnected).
    stored: Option<Bytes>,
}

impl RelayState {
    pub fn new(
        max_channels: usize,
        channel_ttl_secs: u64,
        max_payload_bytes: usize,
        rate_limit_per_min: usize,
    ) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            max_channels,
            channel_ttl_secs,
            connection_log: Mutex::new(HashMap::new()),
            rate_limit_per_min,
            max_payload_bytes,
        }
    }

    /// Check if the given IP is within the rate limit.
    /// Returns true if the connection is allowed, false if rate-limited.
    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut log = self.connection_log.lock().await;
        let entries = log.entry(ip).or_default();
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        entries.retain(|t| *t > cutoff);
        if entries.len() >= self.rate_limit_per_min {
            false
        } else {
            entries.push(Instant::now());
            true
        }
    }
}

/// WebSocket upgrade handler for `/channel/{code}`.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(code): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    // Validate channel code: max 128 chars, alphanumeric and hyphens only
    if code.len() > 128 || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid channel code").into_response();
    }

    if !state.check_rate_limit(addr.ip()).await {
        tracing::warn!(ip = %addr.ip(), "rate limit exceeded");
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )
            .into_response();
    }
    let max_payload = state.max_payload_bytes;
    ws.on_upgrade(move |socket| handle_socket(socket, code, state, max_payload))
        .into_response()
}

async fn handle_socket(
    socket: WebSocket,
    code: String,
    state: Arc<RelayState>,
    max_payload_bytes: usize,
) {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws_tx, mut ws_rx) = socket.split();

    // Clean expired channels first
    {
        let mut channels = state.channels.lock().await;
        let ttl = std::time::Duration::from_secs(state.channel_ttl_secs);
        channels.retain(|_, ch| ch.created_at.elapsed() < ttl);
    }

    // Prune stale IPs from rate limit log to prevent unbounded memory growth
    {
        let mut log = state.connection_log.lock().await;
        let cutoff = Instant::now() - std::time::Duration::from_secs(60);
        log.retain(|_, entries| {
            entries.retain(|t| *t > cutoff);
            !entries.is_empty()
        });
    }

    let mut channels = state.channels.lock().await;

    if let Some(channel) = channels.remove(&code) {
        // === SECOND CLIENT (receiver) ===
        drop(channels);

        if let Some(stored) = channel.stored {
            // Store-and-forward: deliver pre-stored payload immediately
            tracing::debug!(code = %code, "delivering stored payload to receiver");
            let _ = ws_tx.send(Message::Binary(stored.to_vec())).await;
            // Wait for ack or close from receiver before closing our side
            while let Some(msg) = ws_rx.next().await {
                match msg {
                    Ok(Message::Binary(_)) | Ok(Message::Close(_)) => break,
                    Err(_) => break,
                    _ => continue,
                }
            }
            let _ = ws_tx.send(Message::Close(None)).await;
            tracing::debug!(code = %code, "store-and-forward delivery complete");
            return;
        }

        // Live relay: pair with the waiting first client
        let first_client_tx = channel.to_first;
        let first_client_rx = channel.from_first.expect("channel should have from_first");

        tracing::debug!(code = %code, "second client connected, starting live relay");

        let mut first_client_rx = first_client_rx;

        // Forward: first client -> second client
        let mut forward_first = tokio::spawn(async move {
            while let Some(msg) = first_client_rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Forward: second client -> first client
        let max_payload_second = max_payload_bytes;
        let mut forward_second = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                let msg_size = match &msg {
                    Message::Binary(data) => data.len(),
                    Message::Text(text) => text.len(),
                    _ => 0,
                };
                if msg_size > max_payload_second {
                    tracing::warn!(
                        "payload size {} exceeds limit {}",
                        msg_size,
                        max_payload_second
                    );
                    break;
                }
                if first_client_tx.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = first_client_tx.send(Message::Close(None)).await;
        });

        tokio::select! {
            _ = &mut forward_first => {
                forward_second.abort();
            }
            _ = &mut forward_second => {
                forward_first.abort();
            }
        }

        tracing::debug!(code = %code, "live relay session ended");
    } else {
        // === FIRST CLIENT (sender) ===
        if channels.len() >= state.max_channels {
            drop(channels);
            tracing::warn!("max channels reached, rejecting connection");
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }

        let (to_first_tx, mut to_first_rx) = mpsc::channel::<Message>(32);
        let (from_first_tx, from_first_rx) = mpsc::channel::<Message>(32);

        channels.insert(
            code.clone(),
            Channel {
                to_first: to_first_tx,
                from_first: Some(from_first_rx),
                created_at: Instant::now(),
                stored: None,
            },
        );
        drop(channels);

        tracing::debug!(code = %code, "first client connected, waiting for action");

        // Detect mode:
        //   - First client sends binary → store-and-forward (sender exits, channel kept)
        //   - to_first_rx fires first → second client connected first (live relay)
        //   - First client closes without sending → clean up
        // Detect mode:
        //   - First client sends binary → store-and-forward (return early, channel stays)
        //   - to_first_rx fires first → second client connected first (break to live relay)
        //   - First client closes without sending → clean up and return
        'detect: loop {
            tokio::select! {
                msg = ws_rx.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            let len = data.len();
                            if len > max_payload_bytes {
                                tracing::warn!(
                                    "payload size {} exceeds limit {}",
                                    len,
                                    max_payload_bytes
                                );
                                let _ = ws_tx.send(Message::Close(None)).await;
                                let mut ch = state.channels.lock().await;
                                ch.remove(&code);
                                return;
                            }
                            // Store payload in channel for receiver to pick up later
                            {
                                let mut ch = state.channels.lock().await;
                                if let Some(channel) = ch.get_mut(&code) {
                                    channel.stored = Some(Bytes::from(data));
                                }
                            }
                            // Acknowledge sender so they can disconnect
                            let _ = ws_tx.send(Message::Binary(b"ack".to_vec())).await;
                            let _ = ws_tx.send(Message::Close(None)).await;
                            tracing::debug!(code = %code, "payload stored, sender disconnecting");
                            // Channel stays in map with stored data for receiver
                            return;
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            let mut ch = state.channels.lock().await;
                            ch.remove(&code);
                            tracing::debug!(code = %code, "first client disconnected before sending");
                            return;
                        }
                        Some(Err(_)) => {
                            let mut ch = state.channels.lock().await;
                            ch.remove(&code);
                            return;
                        }
                        _ => continue 'detect, // ignore pings, text frames, etc.
                    }
                }
                msg = to_first_rx.recv() => {
                    // Second client connected and relayed a message to first client.
                    // Forward that first message now, then fall through to live relay.
                    if let Some(relay_msg) = msg {
                        if ws_tx.send(relay_msg).await.is_err() {
                            let mut ch = state.channels.lock().await;
                            ch.remove(&code);
                            return;
                        }
                    }
                    break 'detect;
                }
            }
        }

        // Live relay mode: second client connected before first client pushed data.
        // All other paths above have returned already.
        let max_payload_first = max_payload_bytes;
        let mut forward_outgoing = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                let msg_size = match &msg {
                    Message::Binary(data) => data.len(),
                    Message::Text(text) => text.len(),
                    _ => 0,
                };
                if msg_size > max_payload_first {
                    tracing::warn!(
                        "payload size {} exceeds limit {}",
                        msg_size,
                        max_payload_first
                    );
                    break;
                }
                if from_first_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let mut forward_incoming = tokio::spawn(async move {
            while let Some(msg) = to_first_rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        tokio::select! {
            _ = &mut forward_outgoing => {
                forward_incoming.abort();
            }
            _ = &mut forward_incoming => {
                forward_outgoing.abort();
            }
        }

        let mut ch = state.channels.lock().await;
        ch.remove(&code);
        tracing::debug!(code = %code, "first client live relay ended");
    }
}
