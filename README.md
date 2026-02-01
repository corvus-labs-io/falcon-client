# falcon-client

Rust client library for submitting Solana transactions to Falcon via QUIC.

## Installation

```toml
[dependencies]
falcon-client = { git = "https://github.com/corvus-labs-io/falcon-client" }
```

## Quick Start

```rust
use falcon_client::FalconClient;
use solana_transaction::versioned::VersionedTransaction;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = Uuid::parse_str("your-api-key-here")?;
    let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    let transaction: VersionedTransaction = /* your transaction */;
    client.send_transaction(&transaction).await?;

    Ok(())
}
```

## How It Works

The client opens a QUIC connection from your application to Falcon. Transactions are serialized with bincode and sent over unidirectional QUIC streams — one stream per transaction.

Authentication uses mTLS: your API key is embedded in a self-signed client certificate, which Falcon validates on connection. No additional auth headers or tokens are needed after the initial handshake.

If the connection drops, `send_transaction` reconnects automatically before retrying the send. Concurrent callers are coalesced — only one reconnect happens at a time.

## Connection Parameters

All timeouts are compile-time constants:

| Parameter            | Value | Description                              |
| -------------------- | ----- | ---------------------------------------- |
| Keep-alive interval  | 25s   | QUIC keep-alive ping interval            |
| Idle timeout         | 30s   | Connection closed after inactivity       |
| Connect timeout      | 5s    | Initial connection timeout               |
| Stream open timeout  | 200ms | Timeout for opening a unidirectional stream |
| Write timeout        | 500ms | Transaction send timeout                 |

## Transport Details

- **Protocol**: QUIC via [quinn](https://docs.rs/quinn)
- **TLS**: rustls with X25519 key exchange, client certificate authentication
- **ALPN**: `falcon-tx`
- **Serialization**: bincode
- **Streams**: Unidirectional, one per transaction

## License

Apache-2.0
