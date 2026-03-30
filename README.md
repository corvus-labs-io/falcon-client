# falcon-client

`falcon-client` submits Solana `VersionedTransaction`s to Falcon over QUIC.

It maintains a persistent mTLS connection, defaults to reliable stream delivery, and retries one failed send after reconnecting once (using 0-RTT when session tickets are available).

## Installation

```toml
[dependencies]
falcon-client = { git = "https://github.com/corvus-labs-io/falcon-client" }
bytes = "1" # only needed for send_transaction_bytes
uuid = "1"
```

## API at a glance

| API                                                                   | Purpose                                                     |
| --------------------------------------------------------------------- | ----------------------------------------------------------- |
| `FalconClient::connect(endpoint_addr, api_key)`                       | Connect using an ephemeral local UDP port                   |
| `FalconClient::connect_with_bind(endpoint_addr, api_key, local_addr)` | Connect using a fixed local bind address/port               |
| `FalconClient::connect_with_config(endpoint_addr, api_key, config)`   | Connect with explicit client config                         |
| `FalconClientConfig::with_bind_addr(local_addr)`                      | Set local bind address                                      |
| `FalconClientConfig::with_mtu_discovery(enabled)`                     | Enable/disable MTU discovery for future connections         |
| `client.send_transaction(&tx)`                                        | Serialize a `VersionedTransaction` with wincode and send it |
| `client.send_transaction_bytes(payload)`                              | Send pre-serialized `Bytes`                                 |
| `client.send_transaction_payload(payload)`                            | Send a pre-serialized `&[u8]`                               |
| `client.set_transport_mode(mode)`                                     | Switch between stream and datagram delivery                 |
| `client.set_send_timeout(duration)`                                   | Override stream-mode send timeout                           |
| `client.is_connected()`                                               | Check whether the current QUIC connection is open           |
| `client.close()`                                                      | Gracefully close the connection                             |

## Quick start

```rust
use falcon_client::FalconClient;
use solana_transaction::versioned::VersionedTransaction;
use uuid::Uuid;

async fn example(tx: VersionedTransaction) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
    let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    client.send_transaction(&tx).await?;

    assert!(client.is_connected());
    client.close();
    Ok(())
}
```

## Binding a fixed local port

Use `connect_with_bind` when the local UDP port must be fixed, for example for firewall allowlisting.

```rust
use falcon_client::FalconClient;
use std::net::SocketAddr;
use uuid::Uuid;

async fn example(api_key: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    let local_addr: SocketAddr = "0.0.0.0:5002".parse()?;
    let client = FalconClient::connect_with_bind("fra.falcon.wtf:5000", api_key, local_addr).await?;
    client.close();
    Ok(())
}
```

## Transport modes

### `TransportMode::Stream` (default)

Reliable delivery using a bidirectional QUIC stream. Each send opens a bidi stream, writes a `0x01` prefix followed by the serialized payload, and waits for a 2-byte server response.

### `TransportMode::Datagram`

Fire-and-forget delivery using a single QUIC datagram. No stream overhead — `Ok(())` only means the datagram was queued locally; it may still be dropped in transit.

### Switching modes

```rust
use falcon_client::{FalconClient, TransportMode};
use solana_transaction::versioned::VersionedTransaction;
use std::time::Duration;
use uuid::Uuid;

async fn example(api_key: Uuid, tx: VersionedTransaction) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    client.set_send_timeout(Duration::from_millis(200));
    client.send_transaction(&tx).await?;

    client.set_transport_mode(TransportMode::Datagram);
    client.send_transaction(&tx).await?;

    client.close();
    Ok(())
}
```

## Sending pre-serialized payloads

```rust
use bytes::Bytes;
use falcon_client::{serialize_transaction, FalconClient};
use solana_transaction::versioned::VersionedTransaction;
use uuid::Uuid;

async fn example(api_key: Uuid, tx: VersionedTransaction) -> Result<(), Box<dyn std::error::Error>> {
    let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    let payload = serialize_transaction(&tx)?;
    client.send_transaction_payload(&payload).await?;
    client.send_transaction_bytes(Bytes::from(payload)).await?;

    client.close();
    Ok(())
}
```

## Handling errors

All send methods return `anyhow::Result<()>`. Server-side rejections can be downcast to `SubmitError`.

```rust
use falcon_client::{FalconClient, SubmitError};
use solana_transaction::versioned::VersionedTransaction;
use uuid::Uuid;

async fn example(api_key: Uuid, tx: VersionedTransaction) -> Result<(), Box<dyn std::error::Error>> {
    let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    match client.send_transaction(&tx).await {
        Ok(()) => {}
        Err(err) => match err.downcast_ref::<SubmitError>() {
            Some(SubmitError::RateLimited) => eprintln!("rate limited"),
            Some(other) => eprintln!("submission rejected: {other}"),
            None => eprintln!("transport error: {err}"),
        },
    }

    client.close();
    Ok(())
}
```

## `SubmitError`

| Variant                  | Meaning                                       |
| ------------------------ | --------------------------------------------- |
| `RateLimited`            | Server rate-limited the submission            |
| `Unsigned`               | Transaction has no valid signature            |
| `MissingTip`             | Required tip was missing                      |
| `DeserializeFailed`      | Server could not deserialize the payload      |
| `TooLarge`               | Transaction exceeded the maximum allowed size |
| `ForwardFailed`          | Server failed to forward the transaction      |
| `SignatureCountMismatch` | Signature count did not match the message     |
| `Unknown(u8)`            | Unrecognized server error code                |

## Reconnect behavior

On send failure, the client reconnects once (using 0-RTT if session tickets are available) and retries the send. Reconnects are serialized to prevent stampede — if another task already replaced the connection, the current task reuses it.

## Connection defaults

| Setting             | Value       |
| ------------------- | ----------- |
| Keep-alive interval | 60s         |
| Max idle timeout    | 120s        |
| Connect timeout     | 5s          |
| Stream send timeout | 100ms       |
| Initial MTU         | 1472        |
| Initial RTT         | 10ms        |
| ALPN                | `falcon-tx` |
| Default transport   | Stream      |

## TLS

- QUIC via `quinn`, TLS via `rustls`
- X25519 key exchange only
- mTLS with self-signed client certificate; API key embedded in CN
- Server certificate chains are not CA-validated; handshake signatures are verified

## License

Apache-2.0
