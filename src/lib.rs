//! Rust client for submitting Solana transactions to Falcon via QUIC.
//!
//! # Transport modes
//!
//! | Mode | Delivery | Best for |
//! |------|----------|----------|
//! | [`TransportMode::Stream`] (default) | Reliable (QUIC retransmits) | Remote users, guaranteed delivery |
//! | [`TransportMode::Datagram`] (opt-in) | Fire-and-forget | Co-located users, custom retry logic |
//!
//! # Quick start
//!
//! ```no_run
//! use falcon_client::{FalconClient, TransportMode};
//! use solana_transaction::versioned::VersionedTransaction;
//! use uuid::Uuid;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let api_key = Uuid::parse_str("your-api-key-here")?;
//! let mut client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;
//!
//! // Switch to datagrams if co-located with Falcon (same DC).
//! client.set_transport_mode(TransportMode::Datagram);
//!
//! let transaction: VersionedTransaction = todo!();
//! client.send_transaction(&transaction).await?;
//! # Ok(())
//! # }
//! ```
//! # Debug mode
//!
//! Call [`FalconClient::subscribe_debug`] to receive real-time processing
//! events for your transactions. See [`DebugEvent`] for event types.
//!

mod debug;
mod tls;
mod wire;

pub use debug::{DebugEvent, DebugEventKind};
pub use wire::{deserialize_transaction, serialize_transaction};

use {
    anyhow::{Context, Result, anyhow},
    arc_swap::ArcSwap,
    debug::{CONTROL_SUBSCRIBE, MAX_DEBUG_EVENT_SIZE, STREAM_PREFIX_CONTROL},
    quinn::{
        ClientConfig, Connection, Endpoint, IdleTimeout, SendDatagramError, TransportConfig,
        VarInt, crypto::rustls::QuicClientConfig,
    },
    rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair},
    solana_transaction::versioned::VersionedTransaction,
    std::{net::SocketAddr, sync::Arc, time::Duration},
    tls::{SkipServerVerification, crypto_provider},
    tokio::sync::Mutex,
    tracing::warn,
    uuid::Uuid,
};

const ALPN_FALCON_TX: &[u8] = b"falcon-tx";
const SERVER_NAME: &str = "falcon";
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_millis(500);
const INITIAL_MTU: u16 = 1472;
const DEBUG_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Selects how transactions are delivered over the QUIC connection.
///
/// Both modes share the same connection. Switching modes via
/// [`FalconClient::set_transport_mode`] takes effect immediately
/// with no reconnect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportMode {
    /// Reliable delivery via unidirectional QUIC streams.
    ///
    /// Each transaction opens a stream, writes the payload, and finishes.
    /// QUIC retransmits lost packets automatically. The combined open +
    /// write + finish operation is bounded by [`FalconClient::set_send_timeout`]
    /// (default 500ms).
    #[default]
    Stream,

    /// Fire-and-forget delivery via QUIC datagrams ([RFC 9221]).
    ///
    /// No stream overhead — the payload is sent in a single QUIC frame.
    /// `send_transaction` returning `Ok` only means the packet was queued
    /// locally; if the UDP packet is dropped on the wire, the transaction
    /// silently never arrives. Recommended when packet loss is negligible
    /// (same datacenter) or the caller handles retries externally.
    ///
    /// Before sending, the client checks [`Connection::max_datagram_size`]
    /// and returns an error if the payload exceeds the path MTU or the
    /// server does not support datagrams.
    ///
    /// [RFC 9221]: https://datatracker.ietf.org/doc/html/rfc9221
    Datagram,
}

fn generate_client_cert(
    api_key: Uuid,
) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| anyhow!("keypair generation failed: {e}"))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, api_key.to_string());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("cert generation failed: {e}"))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow!("key serialization failed: {e}"))?;

    Ok((cert_der, key_der))
}

/// QUIC client for submitting Solana transactions to Falcon.
///
/// Maintains a persistent mTLS connection — the API key is embedded in a
/// self-signed client certificate. If the connection drops, sends
/// automatically reconnect and retry once.
///
/// # Transport modes
///
/// Defaults to [`TransportMode::Stream`] (reliable). Call
/// [`set_transport_mode`](Self::set_transport_mode) to switch to
/// [`TransportMode::Datagram`] for lower-latency fire-and-forget delivery.
/// See [`TransportMode`] for trade-offs.
pub struct FalconClient {
    endpoint: Endpoint,
    client_config: ClientConfig,
    addr: SocketAddr,
    connection: ArcSwap<Connection>,
    reconnect: Mutex<()>,
    transport_mode: TransportMode,
    send_timeout: Duration,
    debug_listener: Mutex<Option<DebugSubscription>>,
}

struct DebugSubscription {
    reader: tokio::task::JoinHandle<()>,
    send: quinn::SendStream,
}

impl FalconClient {
    /// Connects to Falcon, binding to an ephemeral local port.
    pub async fn connect(endpoint_addr: &str, api_key: Uuid) -> Result<Self> {
        Self::connect_with_bind(endpoint_addr, api_key, "0.0.0.0:0".parse()?).await
    }

    /// Connects to Falcon, binding to `local_addr`.
    ///
    /// Use a fixed port (e.g. `0.0.0.0:5002`) when firewall rules must
    /// allowlist the local UDP port.
    pub async fn connect_with_bind(
        endpoint_addr: &str,
        api_key: Uuid,
        local_addr: SocketAddr,
    ) -> Result<Self> {
        let (cert, key) = generate_client_cert(api_key)?;

        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
            .with_safe_default_protocol_versions()
            .context("TLS config failed")?
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_client_auth_cert(vec![cert], key)
            .context("client cert config failed")?;

        crypto.alpn_protocols = vec![ALPN_FALCON_TX.to_vec()];

        let quic_crypto =
            QuicClientConfig::try_from(crypto).map_err(|e| anyhow!("QUIC config failed: {e}"))?;

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("valid timeout"),
        ));
        transport.initial_mtu(INITIAL_MTU);
        transport.mtu_discovery_config(None);
        // Enable datagram negotiation so Datagram mode works without reconnect.
        transport.datagram_receive_buffer_size(Some(65535));
        // Allow server to open uni streams for debug events.
        transport.max_concurrent_uni_streams(VarInt::from_u32(2));
        // Client never accepts server-initiated bi-streams.
        transport.max_concurrent_bidi_streams(VarInt::from_u32(0));

        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client(local_addr)?;
        endpoint.set_default_client_config(client_config.clone());

        let addr = tokio::net::lookup_host(endpoint_addr)
            .await
            .context("DNS lookup failed")?
            .next()
            .ok_or_else(|| anyhow!("address resolution failed: {endpoint_addr}"))?;

        let connection =
            tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, SERVER_NAME)?)
                .await
                .context("connect timeout")??;

        Ok(Self {
            endpoint,
            client_config,
            addr,
            connection: ArcSwap::from_pointee(connection),
            reconnect: Mutex::new(()),
            transport_mode: TransportMode::default(),
            send_timeout: SEND_TIMEOUT,
            debug_listener: Mutex::new(None),
        })
    }

    /// Switches between [`TransportMode::Stream`] and [`TransportMode::Datagram`].
    /// Takes effect on the next send — no reconnect required.
    pub fn set_transport_mode(&mut self, mode: TransportMode) {
        self.transport_mode = mode;
    }

    /// Overrides the send timeout for stream mode (default 500ms).
    /// Covers the full open_uni + write_all + finish cycle.
    /// Has no effect in datagram mode.
    pub fn set_send_timeout(&mut self, timeout: Duration) {
        self.send_timeout = timeout;
    }

    /// Wincode-serializes and sends a transaction.
    ///
    /// Delivery semantics depend on the current [`TransportMode`].
    /// On failure, reconnects and retries once before returning the error.
    pub async fn send_transaction(&self, transaction: &VersionedTransaction) -> Result<()> {
        let payload = wire::serialize_transaction(transaction)
            .map_err(|e| anyhow!("wincode serialize failed: {e}"))?;
        self.send_transaction_payload(&payload).await
    }

    /// Sends a pre-serialized transaction payload. Same retry semantics
    /// as [`send_transaction`](Self::send_transaction).
    pub async fn send_transaction_payload(&self, payload: &[u8]) -> Result<()> {
        if self.try_send(payload).await.is_ok() {
            return Ok(());
        }

        warn!("send failed, reconnecting");
        self.reconnect(true).await?;
        self.try_send(payload).await
    }

    async fn try_send(&self, payload: &[u8]) -> Result<()> {
        match self.transport_mode {
            TransportMode::Stream => self.send_stream(payload).await,
            TransportMode::Datagram => self.send_datagram(payload),
        }
    }

    fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        let conn = self.connection.load();

        let max = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("datagrams not supported by peer"))?;

        if payload.len() > max {
            anyhow::bail!(
                "payload ({} bytes) exceeds max datagram size ({max} bytes)",
                payload.len()
            );
        }

        conn.send_datagram(bytes::Bytes::copy_from_slice(payload))
            .map_err(|e| match e {
                SendDatagramError::UnsupportedByPeer => anyhow!("datagrams not supported by peer"),
                SendDatagramError::Disabled => anyhow!("datagrams disabled in transport config"),
                SendDatagramError::TooLarge => {
                    anyhow!("datagram exceeds path MTU ({} bytes)", payload.len())
                }
                SendDatagramError::ConnectionLost(reason) => {
                    anyhow!("connection lost: {reason}")
                }
            })
    }

    async fn send_stream(&self, payload: &[u8]) -> Result<()> {
        let conn = self.connection.load();
        tokio::time::timeout(self.send_timeout, async {
            let mut stream = conn.open_uni().await?;
            stream.write_all(payload).await?;
            stream.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("send timeout")?
    }

    async fn reconnect(&self, force: bool) -> Result<()> {
        let conn_id_before = self.connection.load().stable_id();

        let _guard = self.reconnect.lock().await;

        let conn_id_after = self.connection.load().stable_id();
        if conn_id_before != conn_id_after {
            return Ok(());
        }

        if !force && self.is_connected() {
            return Ok(());
        }

        let connection = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.endpoint
                .connect_with(self.client_config.clone(), self.addr, SERVER_NAME)?,
        )
        .await
        .context("connect timeout")??;

        self.connection.store(Arc::new(connection));
        Ok(())
    }

    /// Returns `true` if the QUIC connection is active.
    pub fn is_connected(&self) -> bool {
        self.connection.load().close_reason().is_none()
    }

    /// Closes the QUIC connection immediately, notifying the server.
    ///
    /// Sends a CONNECTION_CLOSE frame so the server can reclaim the
    /// connection slot without waiting for idle timeout.
    pub fn close(&self) {
        self.connection.load().close(VarInt::from_u32(0), b"done");
    }

    /// Subscribes to real-time debug events for this connection.
    ///
    /// Opens a bi-directional QUIC stream to the server carrying the
    /// subscribe signal on the send half and debug events on the recv half.
    /// Only one subscription is active at a time — call
    /// [`unsubscribe_debug`](Self::unsubscribe_debug) first to re-subscribe.
    ///
    /// The debug stream has no impact on transaction processing performance.
    pub async fn subscribe_debug(&self) -> Result<tokio::sync::mpsc::Receiver<DebugEvent>> {
        let mut guard = self.debug_listener.lock().await;
        // Auto-clear stale subscription whose reader has already exited (e.g. connection drop).
        if matches!(guard.as_ref(), Some(sub) if sub.reader.is_finished()) {
            guard.take();
        }
        if guard.is_some() {
            anyhow::bail!("already subscribed to debug events \u{2014} call unsubscribe_debug first");
        }

        let conn = self.connection.load_full();

        // Open a bi-stream: send half carries subscribe, recv half delivers events.
        let (send, recv) = tokio::time::timeout(DEBUG_CONTROL_TIMEOUT, async {
            let (mut send, recv) = conn
                .open_bi()
                .await
                .context("failed to open debug bi-stream")?;
            send.write_all(&[STREAM_PREFIX_CONTROL, CONTROL_SUBSCRIBE])
                .await
                .context("failed to send subscribe")?;
            Ok::<_, anyhow::Error>((send, recv))
        })
        .await
        .context("debug subscribe timeout")??;

        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        let reader = tokio::spawn(async move {
            read_debug_stream(recv, tx).await;
        });

        *guard = Some(DebugSubscription { reader, send });
        Ok(rx)
    }

    /// Unsubscribes from debug events without closing the connection.
    ///
    /// Closes the debug bi-stream's send half, which the server interprets as
    /// an unsubscribe. Waits briefly for a final [`DebugEventKind::Unsubscribed`]
    /// event, then tears down the listener. Transaction flow is unaffected.
    pub async fn unsubscribe_debug(&self) -> Result<()> {
        let sub = self.debug_listener.lock().await.take();
        if let Some(mut sub) = sub {
            let _ = sub.send.finish();
            let abort = sub.reader.abort_handle();
            if tokio::time::timeout(Duration::from_millis(200), sub.reader)
                .await
                .is_err()
            {
                abort.abort();
            }
        }
        Ok(())
    }
}

async fn read_debug_stream(mut recv: quinn::RecvStream, tx: tokio::sync::mpsc::Sender<DebugEvent>) {
    loop {
        let mut len_buf = [0u8; 4];
        if recv.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let frame_len = u32::from_le_bytes(len_buf) as usize;
        if frame_len > MAX_DEBUG_EVENT_SIZE {
            break;
        }

        let mut event_buf = vec![0u8; frame_len];
        if recv.read_exact(&mut event_buf).await.is_err() {
            break;
        }

        let Ok(event) = DebugEvent::from_bytes(&event_buf) else {
            continue;
        };
        if tx.send(event).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_uuid() -> Uuid {
        Uuid::from_bytes(rand::random())
    }

    #[test]
    fn generate_client_cert_succeeds_with_valid_uuid() {
        let api_key = random_uuid();

        let result = generate_client_cert(api_key);

        assert!(result.is_ok());
    }

    #[test]
    fn generate_client_cert_returns_certificate_and_key() {
        let api_key = random_uuid();

        let (cert, key) = generate_client_cert(api_key).expect("cert generation");

        assert!(!cert.as_ref().is_empty());
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn generate_client_cert_uses_api_key_in_common_name() {
        let api_key = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let (cert_der, _key) = generate_client_cert(api_key).expect("cert generation");

        let cert_bytes = cert_der.as_ref();
        let api_key_str = api_key.to_string();
        let api_key_bytes = api_key_str.as_bytes();
        assert!(
            cert_bytes
                .windows(api_key_bytes.len())
                .any(|w| w == api_key_bytes),
            "Certificate should contain API key in CN"
        );
    }

    #[test]
    fn generate_client_cert_different_keys_produce_different_certs() {
        let api_key1 = random_uuid();
        let api_key2 = random_uuid();

        let (cert1, _) = generate_client_cert(api_key1).expect("cert1");
        let (cert2, _) = generate_client_cert(api_key2).expect("cert2");

        assert_ne!(cert1.as_ref(), cert2.as_ref());
    }

    #[test]
    fn default_transport_mode_is_stream() {
        assert_eq!(TransportMode::default(), TransportMode::Stream);
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(ALPN_FALCON_TX, b"falcon-tx");
        assert_eq!(SERVER_NAME, "falcon");
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(25));
        assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SEND_TIMEOUT, Duration::from_millis(500));
        assert_eq!(INITIAL_MTU, 1472);
    }
}
