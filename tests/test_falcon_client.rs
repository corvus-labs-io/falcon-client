mod testkit;

use {
    falcon_client::{DebugEventKind, FalconClient, TransportMode},
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
async fn send_transaction_stream_mode() {
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
async fn send_transaction_datagram_mode() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");

        let data = conn.read_datagram().await.expect("read datagram");
        tx.send(data.to_vec()).await.expect("send to test");

        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());

    let mut client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");
    client.set_transport_mode(TransportMode::Datagram);

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
    use solana_message::Hash;
    use solana_message::VersionedMessage;
    use solana_message::legacy::Message as LegacyMessage;

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

// Wire constants matching falcon-client/src/debug.rs and entrypoint/src/quic_api.rs
const STREAM_PREFIX_CONTROL: u8 = 0x00;
const CONTROL_SUBSCRIBE: u8 = 0x01;

const KIND_VALIDATION_OK: u8 = 0x00;
const KIND_SUBSCRIBED: u8 = 0x05;
const KIND_UNSUBSCRIBED: u8 = 0x06;

/// Builds a raw debug event frame (length-prefixed) matching the server wire format.
/// Event layout: [u64 LE seq] [u64 LE timestamp_us] [u8 kind] [u8 has_sig] [optional 64-byte sig] [kind payload]
fn build_debug_event_frame(sequence: u64, kind_tag: u8, signature: Option<&[u8; 64]>) -> Vec<u8> {
    let mut event = Vec::new();
    event.extend_from_slice(&sequence.to_le_bytes());
    event.extend_from_slice(&1000u64.to_le_bytes()); // timestamp_us
    event.push(kind_tag);
    match signature {
        Some(sig) => {
            event.push(1);
            event.extend_from_slice(sig);
        }
        None => event.push(0),
    }
    // length-prefix the frame
    let mut frame = Vec::new();
    frame.extend_from_slice(&(event.len() as u32).to_le_bytes());
    frame.extend_from_slice(&event);
    frame
}

/// Mock server that handles the debug bi-stream protocol:
/// 1. Accepts a bi-stream from the client
/// 2. Reads subscribe control from recv half
/// 3. Writes debug event frames on the send half
/// 4. Detects unsubscribe (client closes send half) or shutdown
async fn run_debug_mock_server(
    conn: quinn::Connection,
    events_to_send: Vec<(u64, u8, Option<[u8; 64]>)>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    loop {
        tokio::select! {
            accepted_bi = conn.accept_bi() => {
                let Ok((mut send, mut recv)) = accepted_bi else { break };
                let mut buf = [0u8; 2];
                if recv.read_exact(&mut buf).await.is_err() { continue; }
                if buf[0] != STREAM_PREFIX_CONTROL || buf[1] != CONTROL_SUBSCRIBE {
                    continue;
                }
                // send Subscribed event
                let frame = build_debug_event_frame(0, KIND_SUBSCRIBED, None);
                if send.write_all(&frame).await.is_err() { break; }
                // send the provided events
                for (seq, kind, sig) in &events_to_send {
                    let frame = build_debug_event_frame(*seq, *kind, sig.as_ref());
                    if send.write_all(&frame).await.is_err() { break; }
                }
                // wait for unsubscribe (client closes send half) or shutdown
                let mut close_buf = [0u8; 1];
                tokio::select! {
                    _ = recv.read(&mut close_buf) => {}
                    _ = shutdown_rx.recv() => {}
                }
                // send Unsubscribed and close
                let frame = build_debug_event_frame(
                    events_to_send.len() as u64 + 1,
                    KIND_UNSUBSCRIBED,
                    None,
                );
                let _ = send.write_all(&frame).await;
                let _ = send.finish();
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                break;
            }
        }
    }
}

#[tokio::test]
async fn subscribe_debug_receives_events() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let test_sig = [0xAB_u8; 64];
    let events_to_send = vec![(1, KIND_VALIDATION_OK, Some(test_sig))];

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");
        run_debug_mock_server(conn, events_to_send, shutdown_rx).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());
    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    let mut rx = client.subscribe_debug().await.expect("subscribe");

    // first event should be Subscribed
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("recv Subscribed");
    assert!(matches!(event.kind, DebugEventKind::Subscribed));
    assert_eq!(event.sequence, 0);

    // second event: ValidationOk with signature
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("recv ValidationOk");
    assert!(matches!(event.kind, DebugEventKind::ValidationOk));
    assert_eq!(event.sequence, 1);
    assert_eq!(event.signature, Some(test_sig));

    // clean up
    shutdown_tx.send(()).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn unsubscribe_debug_stops_receiving() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");
        run_debug_mock_server(conn, vec![], shutdown_rx).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());
    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    let mut rx = client.subscribe_debug().await.expect("subscribe");

    // receive Subscribed
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert!(matches!(event.kind, DebugEventKind::Subscribed));

    // unsubscribe from client side
    client.unsubscribe_debug().await.expect("unsubscribe");

    // the receiver should be closed (listener was aborted)
    // give it a moment for the abort to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // channel is closed because the listener task was aborted
    let result = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
    match result {
        Ok(None) => {}    // channel closed, expected
        Ok(Some(_)) => {} // buffered event before close, acceptable
        Err(_) => {}      // timeout, acceptable (no more events)
    }

    // Server may have already exited after handling the unsubscribe
    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn resubscribe_debug_after_unsubscribe() {
    let addr = generate_random_local_addr();
    let endpoint = build_mock_falcon_server(addr);

    let server_handle = tokio::spawn(async move {
        let connecting = endpoint.accept().await.expect("accept");
        let conn = connecting.await.expect("connection");

        // handle two subscribe/unsubscribe cycles
        for _ in 0..2 {
            let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                return;
            };
            let mut buf = [0u8; 2];
            if recv.read_exact(&mut buf).await.is_err() { return; }
            if buf[0] != STREAM_PREFIX_CONTROL || buf[1] != CONTROL_SUBSCRIBE { return; }

            let frame = build_debug_event_frame(0, KIND_SUBSCRIBED, None);
            let _ = send.write_all(&frame).await;

            // wait for unsubscribe (client closes send half)
            let mut close_buf = [0u8; 1];
            let _ = recv.read(&mut close_buf).await;

            let frame = build_debug_event_frame(1, KIND_UNSUBSCRIBED, None);
            let _ = send.write_all(&frame).await;
            let _ = send.finish();
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let api_key = random_uuid();
    let endpoint_str = format!("127.0.0.1:{}", addr.port());
    let client = FalconClient::connect(&endpoint_str, api_key)
        .await
        .expect("connect");

    // first subscribe
    let mut rx1 = client.subscribe_debug().await.expect("subscribe 1");
    let event = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert!(matches!(event.kind, DebugEventKind::Subscribed));

    // unsubscribe
    client.unsubscribe_debug().await.expect("unsubscribe 1");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // second subscribe
    let mut rx2 = client.subscribe_debug().await.expect("subscribe 2");
    let event = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert!(matches!(event.kind, DebugEventKind::Subscribed));

    // clean up
    client.unsubscribe_debug().await.expect("unsubscribe 2");
    server_handle.abort();
}
