# falcon-client

Rust client library for submitting Solana transactions to Falcon receivers via QUIC.

## Installation

```toml
[dependencies]
falcon-client = { git = "https://github.com/corvus-labs-io/falcon-client" }
```

## Usage

```rust
use falcon_client::FalconClient;
use solana_transaction::versioned::VersionedTransaction;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to Falcon receiver
    let api_key = Uuid::parse_str("your-api-key-here")?;
    let client = FalconClient::connect("falcon.example.com:5001", api_key).await?;

    // Send a transaction
    let transaction: VersionedTransaction = /* your transaction */;
    client.send_transaction(&transaction).await?;

    Ok(())
}
```

## API

### `FalconClient::connect(endpoint: &str, api_key: Uuid) -> Result<Self>`

Establishes a QUIC connection to the Falcon receiver.

- `endpoint` - Receiver address (e.g., `"host:5001"`)
- `api_key` - Your API key for authentication

### `FalconClient::send_transaction(&self, tx: &VersionedTransaction) -> Result<()>`

Sends a transaction to the receiver. Automatically reconnects on connection failure.

### `FalconClient::is_connected(&self) -> bool`

Returns `true` if the QUIC connection is active.

## Features

- **QUIC transport** - Low-latency, multiplexed connections
- **Auto-reconnect** - Transparent reconnection on connection loss
- **Keep-alive** - Maintains connection with 25s keep-alive interval
- **Async** - Built on Tokio for non-blocking I/O

## Configuration

Connection parameters (compile-time):

| Parameter | Value | Description |
|-----------|-------|-------------|
| Keep-alive interval | 25s | QUIC keep-alive ping interval |
| Idle timeout | 30s | Connection closed after inactivity |
| Connect timeout | 5s | Initial connection timeout |
| Write timeout | 500ms | Transaction send timeout |

## License

Apache-2.0
