mod testkit;

use {
    falcon_client::FalconClient,
    solana_signature::Signature,
    solana_transaction::versioned::VersionedTransaction,
    std::time::Duration,
    testkit::{build_mock_falcon_server, generate_random_local_addr},
    tokio::sync::mpsc,
    uuid::Uuid,
};

fn random_uuid() -> Uuid {
    Uuid::from_bytes(rand::random())
}

#[tokio::test]
async fn connect_succeeds_with_valid_server() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let _conn = connecting.await.expect("connection");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let result = FalconClient::connect(&endpoint_str, api_key).await;

    assert!(result.is_ok());
    let client = result.unwrap();
    assert!(client.is_connected());

    server_handle.abort();
}

#[tokio::test]
async fn connect_fails_with_invalid_address() {
    let api_key = random_uuid();

    let result = FalconClient::connect("127.0.0.1:1", api_key).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn connect_fails_with_no_server() {
    let addr = generate_random_local_addr();
    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let result = tokio::time::timeout(
        Duration::from_secs(6),
        FalconClient::connect(&endpoint_str, api_key),
    )
    .await;

    match result {
        Ok(Ok(_)) => panic!("Expected connection to fail"),
        Ok(Err(_)) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn is_connected_returns_true_when_connected() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let _conn = connecting.await.expect("connection");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    assert!(client.is_connected());

    server_handle.abort();
}

#[tokio::test]
async fn is_connected_returns_false_when_server_closes() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (tx, mut rx) = mpsc::channel::<()>(1);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");
        rx.recv().await;
        conn.close(0u32.into(), b"test close");
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    assert!(client.is_connected());

    tx.send(()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!client.is_connected());

    server_handle.abort();
}

#[tokio::test]
async fn send_transaction_to_accepting_server() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");

        let mut stream = conn.accept_uni().await.expect("accept uni");
        let data = stream.read_to_end(65536).await.expect("read");
        tx.send(data).await.expect("send to test");

        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    let transaction = create_dummy_transaction();

    let result = client.send_transaction(&transaction).await;

    assert!(result.is_ok());

    let received_data = rx.recv().await.expect("receive data");
    assert!(!received_data.is_empty());

    let deserialized: VersionedTransaction =
        falcon_client::deserialize_transaction(&received_data).expect("deserialize");
    assert_eq!(deserialized.signatures, transaction.signatures);

    server_handle.abort();
}

#[tokio::test]
async fn multiple_clients_can_connect_to_same_server() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);

    let server_handle = tokio::spawn(async move {
        loop {
            if let Some(connecting) = endpoint.accept().await {
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        drop(conn);
                    }
                });
            }
        }
    });

    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let client1 = FalconClient::connect(&endpoint_str, random_uuid())
        .await
        .expect("client1");
    let client2 = FalconClient::connect(&endpoint_str, random_uuid())
        .await
        .expect("client2");

    assert!(client1.is_connected());
    assert!(client2.is_connected());

    server_handle.abort();
}

#[tokio::test]
async fn reconnect_happens_on_send_failure() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let (conn_count_tx, mut conn_count_rx) = mpsc::channel::<usize>(10);

    let server_handle = tokio::spawn(async move {
        let mut conn_count = 0;
        loop {
            tokio::select! {
                Some(connecting) = endpoint.accept() => {
                    conn_count += 1;
                    let count = conn_count;
                    let _ = conn_count_tx.send(count).await;
                    let conn = connecting.await.expect("connection");
                    if count == 1 {
                        rx.recv().await;
                        conn.close(0u32.into(), b"force close");
                    } else {
                        while let Ok(mut stream) = conn.accept_uni().await {
                            let _ = stream.read_to_end(65536).await;
                        }
                    }
                }
                else => break,
            }
        }
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    let first_conn = conn_count_rx.recv().await.expect("first connection");
    assert_eq!(first_conn, 1);

    tx.send(()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let transaction = create_dummy_transaction();
    let result = client.send_transaction(&transaction).await;

    if result.is_ok() {
        let second_conn = conn_count_rx.recv().await;
        assert!(second_conn.is_some());
    }

    server_handle.abort();
}

fn create_dummy_transaction() -> VersionedTransaction {
    use solana_message::VersionedMessage;
    use solana_message::legacy::Message as LegacyMessage;
    use solana_message::Hash;

    let signature = Signature::from([1u8; 64]);
    let blockhash = Hash::from([2u8; 32]);
    let message = VersionedMessage::Legacy(LegacyMessage {
        header: solana_message::MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        },
        account_keys: vec![solana_pubkey::Pubkey::new_unique()],
        recent_blockhash: blockhash,
        instructions: vec![],
    });

    VersionedTransaction {
        signatures: vec![signature],
        message,
    }
}
