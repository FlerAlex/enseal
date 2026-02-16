#[cfg(feature = "server")]
mod relay_tests {
    use tokio::time::{sleep, Duration};

    /// Start a relay server on a random port and return the port.
    async fn start_relay(ttl: u64) -> u16 {
        let config = enseal::server::ServerConfig {
            port: 0,
            bind: "127.0.0.1".to_string(),
            max_channels: 10,
            channel_ttl_secs: ttl,
        };

        let app = enseal::server::build_router(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
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

                let received = enseal::transfer::relay::receive(&url, &code)
                    .await
                    .unwrap();
                assert_eq!(received, data.as_bytes());
                sender.await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
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
}
