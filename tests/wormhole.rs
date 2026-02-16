//! Integration tests for wormhole-based share/receive round-trips.
//!
//! These tests use the public magic-wormhole relay (`relay.magic-wormhole.io`)
//! and require network access. They are marked `#[ignore]` by default.
//!
//! Run with: `cargo test --test wormhole -- --ignored`

use enseal::cli::input::PayloadFormat;
use enseal::crypto::envelope::Envelope;
use enseal::crypto::signing::SignedEnvelope;
use enseal::keys::identity::EnsealIdentity;
use enseal::transfer;

use tokio::sync::oneshot;

/// Helper: send an envelope through wormhole, returning the code via a channel
/// so the receiver can connect concurrently.
async fn send_with_code(
    envelope: Envelope,
    code_tx: oneshot::Sender<String>,
) {
    let config = transfer::app_config(None);
    let mailbox = magic_wormhole::MailboxConnection::create(config, 2)
        .await
        .unwrap();
    let code = mailbox.code().to_string();
    code_tx.send(code).unwrap();

    let mut wormhole = magic_wormhole::Wormhole::connect(mailbox)
        .await
        .unwrap();
    let data = envelope.to_bytes().unwrap();
    wormhole.send(data).await.unwrap();
    wormhole.close().await.unwrap();
}

/// Anonymous mode: share a .env file, receive it back.
#[tokio::test]
#[ignore]
async fn anonymous_env_round_trip() {
    let content = "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=test_key_abc123\n";
    let envelope = Envelope::seal(content, PayloadFormat::Env, None).unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    assert_eq!(received.format, PayloadFormat::Env);
    assert_eq!(received.payload, content);
    assert_eq!(received.metadata.var_count, Some(3));
}

/// Anonymous mode: share a raw secret string, receive it back.
#[tokio::test]
#[ignore]
async fn anonymous_raw_secret_round_trip() {
    let secret = "sk_live_abc123_test_token";
    let envelope = Envelope::seal(
        secret,
        PayloadFormat::Raw,
        Some("Stripe API key".to_string()),
    )
    .unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    assert_eq!(received.format, PayloadFormat::Raw);
    assert_eq!(received.payload, secret);
    assert_eq!(received.metadata.label.as_deref(), Some("Stripe API key"));
    assert_eq!(received.metadata.var_count, None);
}

/// Anonymous mode: share KEY=VALUE content (simulates --secret KEY=val).
#[tokio::test]
#[ignore]
async fn anonymous_kv_round_trip() {
    let kv_content = "STRIPE_KEY=sk_live_abc123";
    let envelope = Envelope::seal(kv_content, PayloadFormat::Kv, None).unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    assert_eq!(received.format, PayloadFormat::Kv);
    assert_eq!(received.payload, kv_content);
    assert_eq!(received.metadata.var_count, Some(1));
}

/// Simulates pipe input: multi-line .env content detected as Env format.
#[tokio::test]
#[ignore]
async fn pipe_env_round_trip() {
    let content = "SECRET=hunter2\nOTHER=value\n";
    let envelope = Envelope::seal(content, PayloadFormat::Env, None).unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    assert_eq!(received.format, PayloadFormat::Env);
    assert_eq!(received.payload, content);
    assert_eq!(received.metadata.var_count, Some(2));
}

/// Simulates --as KEY wrapping: raw value wrapped as KEY=value in Kv format.
#[tokio::test]
#[ignore]
async fn as_key_wrapping_round_trip() {
    let wrapped = "API_KEY=my_token";
    let envelope = Envelope::seal(wrapped, PayloadFormat::Kv, None).unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    assert_eq!(received.format, PayloadFormat::Kv);
    assert_eq!(received.payload, wrapped);
}

/// Identity mode: share --to via wormhole relay with encryption + signing.
#[tokio::test]
#[ignore]
async fn identity_mode_relay_round_trip() {
    let sender_id = EnsealIdentity::generate();
    let receiver_id = EnsealIdentity::generate();

    let content = "DB_URL=postgres://localhost/mydb\nSECRET=identity_test\n";
    let envelope = Envelope::seal(content, PayloadFormat::Env, None).unwrap();
    let inner_bytes = envelope.to_bytes().unwrap();

    // Encrypt to receiver, sign with sender
    let signed =
        SignedEnvelope::seal(&inner_bytes, &[&receiver_id.age_recipient], &sender_id).unwrap();
    let wire_bytes = signed.to_bytes().unwrap();

    let (code_tx, code_rx) = oneshot::channel();

    // Sender: create mailbox, send code, then send signed envelope
    tokio::spawn(async move {
        let config = transfer::app_config(None);
        let mailbox = magic_wormhole::MailboxConnection::create(config, 2)
            .await
            .unwrap();
        let code = mailbox.code().to_string();
        code_tx.send(code).unwrap();

        let mut wormhole = magic_wormhole::Wormhole::connect(mailbox).await.unwrap();
        wormhole.send(wire_bytes).await.unwrap();
        wormhole.close().await.unwrap();
    });

    let code = code_rx.await.unwrap();

    // Receive and verify + decrypt
    let config = transfer::app_config(None);
    let code_parsed = code.parse().unwrap();
    let mailbox = magic_wormhole::MailboxConnection::connect(config, code_parsed, true)
        .await
        .unwrap();
    let mut wormhole = magic_wormhole::Wormhole::connect(mailbox).await.unwrap();
    let data = wormhole.receive().await.unwrap();
    wormhole.close().await.unwrap();

    let received_signed = SignedEnvelope::from_bytes(&data).unwrap();
    let decrypted_bytes = received_signed.open(&receiver_id, None).unwrap();
    let received_envelope = Envelope::from_bytes(&decrypted_bytes).unwrap();

    assert_eq!(received_envelope.format, PayloadFormat::Env);
    assert_eq!(received_envelope.payload, content);
    assert_eq!(received_envelope.metadata.var_count, Some(2));
}

/// Inject simulation: receive secrets via wormhole, verify they can be
/// extracted as environment variables (without actually spawning a child).
#[tokio::test]
#[ignore]
async fn inject_via_wormhole() {
    let content = "INJECTED_SECRET=supersecret\nINJECTED_PORT=8080\n";
    let envelope = Envelope::seal(content, PayloadFormat::Env, None).unwrap();

    let (code_tx, code_rx) = oneshot::channel();
    tokio::spawn(send_with_code(envelope, code_tx));

    let code = code_rx.await.unwrap();
    let received = transfer::wormhole::receive(&code, None).await.unwrap();

    // Simulate what inject does: extract key-value pairs
    assert_eq!(received.format, PayloadFormat::Env);
    let mut secrets = std::collections::HashMap::new();
    for line in received.payload.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();
            secrets.insert(key, value);
        }
    }

    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets.get("INJECTED_SECRET").unwrap(), "supersecret");
    assert_eq!(secrets.get("INJECTED_PORT").unwrap(), "8080");
}
