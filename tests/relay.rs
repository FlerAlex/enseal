#[cfg(feature = "server")]
mod relay_tests {
    use tokio::time::{sleep, Duration};

    /// Start a relay server on a random port and return the port.
    async fn start_relay(ttl: u64) -> u16 {
        start_relay_with_config(ttl, 1_048_576, 100).await
    }

    /// Start a relay server with custom config and return the port.
    async fn start_relay_with_config(
        ttl: u64,
        max_payload_bytes: usize,
        rate_limit_per_min: usize,
    ) -> u16 {
        let config = enseal::server::ServerConfig {
            port: 0,
            bind: "127.0.0.1".to_string(),
            max_channels: 10,
            channel_ttl_secs: ttl,
            max_payload_bytes,
            rate_limit_per_min,
        };

        let app = enseal::server::build_router(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Give the server a moment to start
        sleep(Duration::from_millis(50)).await;
        port
    }

    #[tokio::test]
    async fn relay_round_trip() {
        let port = start_relay(30).await;
        let relay_url = format!("ws://127.0.0.1:{}", port);
        let code = enseal::transfer::relay::generate_code();

        let data = b"SECRET=hunter2\nAPI_KEY=abc123\n";

        let relay_url_send = relay_url.clone();
        let code_send = code.clone();
        let send_handle = tokio::spawn(async move {
            enseal::transfer::relay::send(data, &relay_url_send, &code_send)
                .await
                .unwrap();
        });

        // Small delay to let sender connect first
        sleep(Duration::from_millis(100)).await;

        let received = enseal::transfer::relay::receive(&relay_url, &code)
            .await
            .unwrap();

        assert_eq!(received, data);
        send_handle.await.unwrap();
    }

    #[tokio::test]
    async fn relay_receiver_first() {
        let port = start_relay(30).await;
        let relay_url = format!("ws://127.0.0.1:{}", port);
        let code = enseal::transfer::relay::generate_code();

        let data = b"FIRST=receiver_connects_first";

        let relay_url_recv = relay_url.clone();
        let code_recv = code.clone();
        let recv_handle = tokio::spawn(async move {
            enseal::transfer::relay::receive(&relay_url_recv, &code_recv)
                .await
                .unwrap()
        });

        // Small delay to let receiver connect first
        sleep(Duration::from_millis(100)).await;

        enseal::transfer::relay::send(data, &relay_url, &code)
            .await
            .unwrap();

        let received = recv_handle.await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn relay_multiple_channels() {
        let port = start_relay(30).await;
        let relay_url = format!("ws://127.0.0.1:{}", port);

        let mut handles = Vec::new();
        for i in 0..3 {
            let url = relay_url.clone();
            let code = enseal::transfer::relay::generate_code();
            let data = format!("CHANNEL_{i}=value_{i}");

            handles.push(tokio::spawn(async move {
                let send_url = url.clone();
                let send_code = code.clone();
                let send_data = data.as_bytes().to_vec();

                let sender = tokio::spawn(async move {
                    enseal::transfer::relay::send(&send_data, &send_url, &send_code)
                        .await
                        .unwrap();
                });

                sleep(Duration::from_millis(100)).await;

                let received = enseal::transfer::relay::receive(&url, &code).await.unwrap();
                assert_eq!(received, data.as_bytes());
                sender.await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn relay_listen_push_round_trip() {
        let port = start_relay(30).await;
        let relay_url = format!("ws://127.0.0.1:{}", port);

        // Generate sender + receiver identities
        let sender = enseal::keys::identity::EnsealIdentity::generate();
        let receiver = enseal::keys::identity::EnsealIdentity::generate();

        // Derive channel ID from receiver's identity (both sides compute this)
        let receiver_channel = receiver.channel_id();

        // Build a test envelope
        let content = "DB_HOST=localhost\nDB_PASS=secret123\n";
        let envelope = enseal::crypto::envelope::Envelope::seal(
            content,
            enseal::cli::input::PayloadFormat::Env,
            None,
        )
        .unwrap();
        let inner_bytes = envelope.to_bytes().unwrap();

        // Encrypt + sign
        let signed = enseal::crypto::signing::SignedEnvelope::seal(
            &inner_bytes,
            &[&receiver.age_recipient],
            &sender,
        )
        .unwrap();
        let wire_bytes = signed.to_bytes().unwrap();

        // Spawn listener (receiver connects first)
        let recv_url = relay_url.clone();
        let recv_channel = receiver_channel.clone();
        let recv_handle = tokio::spawn(async move {
            enseal::transfer::relay::listen(&recv_url, &recv_channel)
                .await
                .unwrap()
        });

        // Small delay to let receiver connect
        sleep(Duration::from_millis(100)).await;

        // Sender pushes
        enseal::transfer::relay::push(&wire_bytes, &relay_url, &receiver_channel)
            .await
            .unwrap();

        // Receiver gets data
        let received_bytes = recv_handle.await.unwrap();

        // Verify + decrypt
        let received_signed =
            enseal::crypto::signing::SignedEnvelope::from_bytes(&received_bytes).unwrap();
        let decrypted = received_signed.open(&receiver, None).unwrap();
        let received_envelope =
            enseal::crypto::envelope::Envelope::from_bytes(&decrypted).unwrap();

        assert_eq!(received_envelope.payload, content);
        assert_eq!(
            received_envelope.metadata.var_count,
            Some(2)
        );
    }

    #[tokio::test]
    async fn health_endpoint() {
        let port = start_relay(30).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("enseal-relay"));
    }

    #[tokio::test]
    async fn relay_payload_size_limit() {
        // Start relay with 1KB max payload
        let port = start_relay_with_config(30, 1024, 100).await;
        let relay_url = format!("ws://127.0.0.1:{}", port);
        let code = enseal::transfer::relay::generate_code();

        // Send 2KB payload — should exceed the limit
        let data = vec![0x42u8; 2048];

        let relay_url_send = relay_url.clone();
        let code_send = code.clone();
        let send_handle = tokio::spawn(async move {
            // send may return an error or succeed (the relay drops the oversized message)
            let _ = enseal::transfer::relay::send(&data, &relay_url_send, &code_send).await;
        });

        sleep(Duration::from_millis(100)).await;

        // Receiver should either get an error or timeout — the oversized message is dropped
        let recv_result = tokio::time::timeout(
            Duration::from_secs(2),
            enseal::transfer::relay::receive(&relay_url, &code),
        )
        .await;

        // Either timed out (message was dropped) or received an error
        assert!(
            recv_result.is_err() || recv_result.unwrap().is_err(),
            "oversized payload should not be delivered"
        );

        send_handle.abort();
    }

    #[tokio::test]
    async fn relay_rate_limit() {
        use tokio_tungstenite::connect_async;

        // Start relay with 2 connections/min rate limit
        let port = start_relay_with_config(30, 1_048_576, 2).await;
        let base_url = format!("ws://127.0.0.1:{}", port);

        // First two connections should succeed (upgrade to WebSocket)
        let url1 = format!("{}/channel/rate-test-1", base_url);
        let conn1 = connect_async(&url1).await;
        assert!(conn1.is_ok(), "first connection should succeed");

        let url2 = format!("{}/channel/rate-test-2", base_url);
        let conn2 = connect_async(&url2).await;
        assert!(conn2.is_ok(), "second connection should succeed");

        // Third connection should be rejected with 429
        let url3 = format!("{}/channel/rate-test-3", base_url);
        let conn3 = connect_async(&url3).await;
        // tungstenite returns an error when the server responds with a non-101 status
        assert!(conn3.is_err(), "third connection should be rate-limited");
    }
}
