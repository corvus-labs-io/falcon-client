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
    
    // FalconClient::connect binds to an ephemeral port. 
    // Use connect_with_bind to specify a static local port for firewall rules.
    let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;

    let transaction: VersionedTransaction = /* your transaction */;
    client.send_transaction(&transaction).await?;

    Ok(())
}
```

## Transport Modes

The client supports two delivery mechanisms: reliable streams and unreliable datagrams.

### User Personas

* **Co-located users**: Applications in the same datacenter as Falcon (FRA) experience near-zero packet loss. Datagrams are recommended for lowest latency by removing stream-open overhead.
* **Fire-and-forget users**: Applications implementing custom retry logic or inclusion checking can use datagrams. Transport-level reliability is redundant in these workflows.
* **Remote or reliability-critical users**: Applications connecting over the public internet or requiring guaranteed delivery to the Falcon ingress should use streams (default).

### Which mode should I use?

| Scenario | Recommended Mode | Why |
| :--- | :--- | :--- |
| Same DC as Falcon | Datagram | Lowest latency, ~0% packet loss |
| Custom retry logic | Datagram | Avoids redundant transport reliability |
| Public internet | Stream | QUIC handles packet loss retransmission |
| Critical delivery | Stream | Guaranteed arrival at ingress |

### Reliability Details

In **Datagram** mode, `send_transaction` returning `Ok` only confirms the packet was handed to the local network stack. If the UDP packet is dropped on the wire, the transaction silently never arrives.

In **Stream** mode, the client opens a unidirectional QUIC stream for each transaction. QUIC automatically handles retransmissions if packets are lost, ensuring the transaction reaches the server.

## Usage Examples

### Stream Mode (Default)

```rust
let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;
client.send_transaction(&tx).await?;
```

Customize the stream send timeout (default 500ms):
```rust
use std::time::Duration;
client.set_send_timeout(Duration::from_millis(200));
```

### Datagram Mode (Opt-in)

```rust
use falcon_client::TransportMode;

let mut client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;
client.set_transport_mode(TransportMode::Datagram);
client.send_transaction(&tx).await?;
```

## Debug Mode (Opt-in)

Opt-in real-time event stream showing how your transactions are being processed server-side.

```rust
let mut rx = client.subscribe_debug().await?;

// Receive events in a background task or loop
tokio::spawn(async move {
    while let Some(event) = rx.recv().await {
        println!("seq={} kind={:?}", event.sequence, event.kind);
    }
});

// Later, unsubscribe without closing the connection
client.unsubscribe_debug().await?;
```

| Event | Fields | Meaning |
|-------|--------|---------|
| ValidationOk | signature | Transaction passed validation |
| ValidationErr | signature, reason | Validation failed |
| ForwardOk | signature, latencies, bridges, failover | Forwarded to network |
| ForwardErr | signature, reason | Forward failed |
| EventsDropped | count | Debug channel was full, events lost |
| Subscribed | — | Subscription confirmed |
| Unsubscribed | — | Unsubscription confirmed |

* Sequence numbers are monotonic per connection, gaps indicate dropped events.
* Debug mode has zero impact on transaction processing (non-blocking).
* Only one active subscription per connection, call `unsubscribe_debug` before re-subscribing.


## Connection Parameters

| Parameter | Value | Description |
| :--- | :--- | :--- |
| Keep-alive interval | 25s | QUIC keep-alive ping interval |
| Idle timeout | 30s | Connection closed after inactivity |
| Connect timeout | 5s | Initial connection timeout |
| Send timeout | 500ms | Stream open and write timeout (stream only) |
| Initial MTU | 1472 | Matches Falcon server MTU |

## Transport Details

* **Protocol**: QUIC via quinn
* **TLS**: rustls with X25519 and mTLS client certificates
* **ALPN**: `falcon-tx`
* **Serialization**: wincode

## License

Apache-2.0
