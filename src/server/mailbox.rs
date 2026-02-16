use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

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
}

struct Channel {
    /// Sender to the first client waiting in this channel.
    tx: mpsc::Sender<Message>,
    /// Receiver that the first client reads from (gets paired client's messages).
    rx: Option<mpsc::Receiver<Message>>,
    created_at: Instant,
}

impl RelayState {
    pub fn new(max_channels: usize, channel_ttl_secs: u64) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            max_channels,
            channel_ttl_secs,
        }
    }
}

/// WebSocket upgrade handler for `/channel/{code}`.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(code): Path<String>,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, code, state))
}

async fn handle_socket(socket: WebSocket, code: String, state: Arc<RelayState>) {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws_tx, mut ws_rx) = socket.split();

    // Clean expired channels first
    {
        let mut channels = state.channels.lock().await;
        let ttl = std::time::Duration::from_secs(state.channel_ttl_secs);
        channels.retain(|_, ch| ch.created_at.elapsed() < ttl);
    }

    // Try to join an existing channel or create a new one
    let mut channels = state.channels.lock().await;

    if let Some(channel) = channels.remove(&code) {
        // Second client: pair with the waiting client
        let first_client_tx = channel.tx;
        let first_client_rx = channel.rx.expect("channel should have rx");
        drop(channels); // Release the lock

        tracing::debug!(code = %code, "second client connected, starting relay");

        // Create channel for second client -> first client
        let (second_to_first_tx, second_to_first_rx) = mpsc::channel::<Message>(32);

        // Spawn task to send second_to_first messages to first client
        // (first client will read from first_client_rx which gets second client's messages)
        // Actually, we need to rethink: first client is waiting, we need bidirectional relay.

        // Channel pair:
        // first_client_tx: sends TO first client (second client's messages go here)
        // first_client_rx: receives FROM first client (first client's messages come here)

        // We need to relay:
        // ws_rx (second client sends) -> first_client_tx (to first client)
        // first_client_rx (first client sends) -> ws_tx (to second client)

        let mut first_client_rx = first_client_rx;

        // Forward: first client -> second client
        let forward_first = tokio::spawn(async move {
            while let Some(msg) = first_client_rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Forward: second client -> first client
        let forward_second = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                if first_client_tx.send(msg).await.is_err() {
                    break;
                }
            }
            // Signal close
            let _ = first_client_tx.send(Message::Close(None)).await;
        });

        // Wait for either to finish
        tokio::select! {
            _ = forward_first => {}
            _ = forward_second => {}
        }

        drop(second_to_first_tx);
        drop(second_to_first_rx);

        tracing::debug!(code = %code, "relay session ended");
    } else {
        // First client: create a channel and wait
        if channels.len() >= state.max_channels {
            drop(channels);
            tracing::warn!("max channels reached, rejecting connection");
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }

        // Create two channel pairs for bidirectional relay:
        // to_first_tx/to_first_rx: messages TO the first client
        // from_first_tx/from_first_rx: messages FROM the first client
        let (to_first_tx, mut to_first_rx) = mpsc::channel::<Message>(32);
        let (from_first_tx, from_first_rx) = mpsc::channel::<Message>(32);

        channels.insert(
            code.clone(),
            Channel {
                tx: to_first_tx,
                rx: Some(from_first_rx),
                created_at: Instant::now(),
            },
        );
        drop(channels); // Release the lock

        tracing::debug!(code = %code, "first client connected, waiting for pair");

        // Forward: first client sends -> from_first_tx (stored for second client)
        let code_clone = code.clone();
        let forward_outgoing = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                if from_first_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Forward: to_first_rx (from second client) -> first client ws
        let forward_incoming = tokio::spawn(async move {
            while let Some(msg) = to_first_rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        tokio::select! {
            _ = forward_outgoing => {}
            _ = forward_incoming => {}
        }

        // Clean up channel if still waiting (second client never connected)
        let mut channels = state.channels.lock().await;
        channels.remove(&code_clone);

        tracing::debug!(code = %code_clone, "first client disconnected");
    }
}
