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
//! // Datagrams are available for lowest latency when packet loss is negligible.
//! client.set_transport_mode(TransportMode::Datagram);
//!
//! let transaction: VersionedTransaction = todo!();
//! client.send_transaction(&transaction).await?;
//! # Ok(())
//! # }
//! ```

mod tls;
mod wire;

pub use wire::{deserialize_transaction, serialize_transaction};

use {
    anyhow::{Context, Result, anyhow},
    arc_swap::ArcSwap,
    bytes::Bytes,
    quinn::{
        AckFrequencyConfig, ClientConfig, Connection, Endpoint, EndpointConfig, IdleTimeout,
        SendDatagramError, TransportConfig, VarInt, crypto::rustls::QuicClientConfig,
    },
    rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair},
    socket2::{Domain, Protocol, Socket, Type},
    solana_transaction::versioned::VersionedTransaction,
    std::{
        net::{SocketAddr, UdpSocket},
        sync::Arc,
        time::Duration,
    },
    tls::{SkipServerVerification, crypto_provider},
    tokio::sync::Mutex,
    tracing::warn,
    uuid::Uuid,
};

const ALPN_FALCON_TX: &[u8] = b"falcon-tx";
const SERVER_NAME: &str = "falcon";
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_millis(100);
const INITIAL_MTU: u16 = 1472;
const INITIAL_RTT: Duration = Duration::from_millis(10);

/// Selects how transactions are delivered over the QUIC connection.
///
/// Both modes share the same connection. Switching modes via
/// [`FalconClient::set_transport_mode`] takes effect immediately
/// with no reconnect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportMode {
    /// Reliable delivery via bidirectional QUIC streams.
    ///
    /// Each transaction opens a stream, writes the payload, then waits for a
    /// server ack. QUIC retransmits lost packets automatically. The combined
    /// open + write + ack roundtrip is bounded by
    /// [`FalconClient::set_send_timeout`] (default 500ms).
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

/// Optional client connection settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FalconClientConfig {
    local_addr: SocketAddr,
    mtu_discovery: bool,
}

impl Default for FalconClientConfig {
    fn default() -> Self {
        Self {
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            mtu_discovery: true,
        }
    }
}

impl FalconClientConfig {
    /// Binds the client socket to `local_addr`.
    pub fn with_bind_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = local_addr;
        self
    }

    /// Enables or disables DPLPMTUD for future connections.
    pub fn with_mtu_discovery(mut self, enabled: bool) -> Self {
        self.mtu_discovery = enabled;
        self
    }
}

/// Error returned when the server rejects a transaction submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// Server rate-limited this submission.
    RateLimited,
    /// Transaction has no valid signature.
    Unsigned,
    /// Transaction does not include required tip.
    MissingTip,
    /// Could not deserialize the transaction.
    DeserializeFailed,
    /// Transaction exceeds maximum allowed size.
    TooLarge,
    /// Server failed to forward the transaction.
    ForwardFailed,
    /// Transaction signature count does not match.
    SignatureCountMismatch,
    /// Server returned an unknown error code.
    Unknown(u8),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited => write!(f, "rate limited"),
            Self::Unsigned => write!(f, "unsigned transaction"),
            Self::MissingTip => write!(f, "missing required tip"),
            Self::DeserializeFailed => write!(f, "failed to deserialize transaction"),
            Self::TooLarge => write!(f, "transaction too large"),
            Self::ForwardFailed => write!(f, "server failed to forward transaction"),
            Self::SignatureCountMismatch => write!(f, "signature count mismatch"),
            Self::Unknown(code) => write!(f, "unknown server error (code {code:#x})"),
        }
    }
}

impl std::error::Error for SubmitError {}

impl SubmitError {
    fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::RateLimited,
            0x02 => Self::Unsigned,
            0x03 => Self::MissingTip,
            0x04 => Self::DeserializeFailed,
            0x05 => Self::TooLarge,
            0x06 => Self::ForwardFailed,
            0x07 => Self::SignatureCountMismatch,
            other => Self::Unknown(other),
        }
    }
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
/// Defaults to [`TransportMode::Stream`] (reliable delivery). Call
/// [`set_transport_mode`](Self::set_transport_mode) to switch to
/// [`TransportMode::Datagram`] for fire-and-forget delivery with lowest latency.
/// See [`TransportMode`] for trade-offs.
pub struct FalconClient {
    endpoint: Endpoint,
    client_config: ClientConfig,
    addr: SocketAddr,
    connection: ArcSwap<Connection>,
    reconnect: Mutex<()>,
    transport_mode: TransportMode,
    send_timeout: Duration,
}

impl FalconClient {
    /// Connects to Falcon, binding to an ephemeral local port.
    pub async fn connect(endpoint_addr: &str, api_key: Uuid) -> Result<Self> {
        Self::connect_with_config(endpoint_addr, api_key, FalconClientConfig::default()).await
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
        Self::connect_with_config(
            endpoint_addr,
            api_key,
            FalconClientConfig::default().with_bind_addr(local_addr),
        )
        .await
    }

    /// Connects to Falcon using an explicit client configuration.
    pub async fn connect_with_config(
        endpoint_addr: &str,
        api_key: Uuid,
        config: FalconClientConfig,
    ) -> Result<Self> {
        let client_config = build_client_config(api_key, config.mtu_discovery)?;
        let endpoint = build_endpoint(config.local_addr, &client_config)?;

        let addr = tokio::net::lookup_host(endpoint_addr)
            .await
            .context("DNS lookup failed")?
            .next()
            .ok_or_else(|| anyhow!("address resolution failed: {endpoint_addr}"))?;

        let connection = connect_with_handshake(&endpoint, client_config.clone(), addr).await?;

        Ok(Self {
            endpoint,
            client_config,
            addr,
            connection: ArcSwap::from_pointee(connection),
            reconnect: Mutex::new(()),
            transport_mode: TransportMode::default(),
            send_timeout: SEND_TIMEOUT,
        })
    }

    /// Switches between [`TransportMode::Stream`] and [`TransportMode::Datagram`].
    /// Takes effect on the next send — no reconnect required.
    pub fn set_transport_mode(&mut self, mode: TransportMode) {
        self.transport_mode = mode;
    }

    /// Overrides the send timeout for stream mode (default 500ms).
    /// Covers the full open_bi + write_all + response cycle.
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
        self.send_transaction_bytes(Bytes::from(payload)).await
    }

    /// Sends a pre-serialized transaction payload without copying owned bytes.
    ///
    /// Same retry semantics as [`send_transaction`](Self::send_transaction).
    pub async fn send_transaction_bytes(&self, payload: Bytes) -> Result<()> {
        if self.try_send(payload.clone()).await.is_ok() {
            return Ok(());
        }

        warn!("send failed, reconnecting");
        self.reconnect(true).await?;
        self.try_send(payload).await
    }

    /// Sends a pre-serialized transaction payload. Same retry semantics
    /// as [`send_transaction`](Self::send_transaction).
    pub async fn send_transaction_payload(&self, payload: &[u8]) -> Result<()> {
        self.send_transaction_bytes(Bytes::copy_from_slice(payload))
            .await
    }

    async fn try_send(&self, payload: Bytes) -> Result<()> {
        match self.transport_mode {
            TransportMode::Stream => self.send_stream(payload.as_ref()).await,
            TransportMode::Datagram => self.send_datagram(payload),
        }
    }

    fn send_datagram(&self, payload: Bytes) -> Result<()> {
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

        let payload_len = payload.len();
        conn.send_datagram(payload).map_err(|e| match e {
            SendDatagramError::UnsupportedByPeer => anyhow!("datagrams not supported by peer"),
            SendDatagramError::Disabled => anyhow!("datagrams disabled in transport config"),
            SendDatagramError::TooLarge => {
                anyhow!("datagram exceeds path MTU ({payload_len} bytes)")
            }
            SendDatagramError::ConnectionLost(reason) => anyhow!("connection lost: {reason}"),
        })
    }

    async fn send_stream(&self, payload: &[u8]) -> Result<()> {
        let conn = self.connection.load();
        tokio::time::timeout(self.send_timeout, async {
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(&[0x01]).await?;
            send.write_all(payload).await?;
            send.finish()?;

            let mut resp = [0u8; 2];
            recv.read_exact(&mut resp)
                .await
                .context("failed to read server response")?;

            if resp[1] == 0x00 {
                Ok(())
            } else {
                Err(SubmitError::from_code(resp[1]).into())
            }
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

        let connecting =
            self.endpoint
                .connect_with(self.client_config.clone(), self.addr, SERVER_NAME)?;

        let connection = match connecting.into_0rtt() {
            Ok((connection, zero_rtt_accepted)) => {
                // Wait for server to accept 0-RTT before using the connection.
                // The connection is usable either way — if 0-RTT is accepted, the wait is nearly instant.
                // If rejected, the wait is one RTT while the handshake completes.
                match tokio::time::timeout(CONNECT_TIMEOUT, zero_rtt_accepted).await {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!("server rejected 0-RTT on reconnect");
                    }
                    Err(_) => {
                        warn!("timed out waiting for 0-RTT confirmation");
                    }
                }
                connection
            }
            Err(connecting) => tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                .await
                .context("connect timeout")??,
        };

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
}

fn build_client_config(api_key: Uuid, mtu_discovery: bool) -> Result<ClientConfig> {
    let (cert, key) = generate_client_cert(api_key)?;

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_safe_default_protocol_versions()
        .context("TLS config failed")?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_client_auth_cert(vec![cert], key)
        .context("client cert config failed")?;

    crypto.enable_early_data = true;
    crypto.alpn_protocols = vec![ALPN_FALCON_TX.to_vec()];

    let quic_crypto =
        QuicClientConfig::try_from(crypto).map_err(|e| anyhow!("QUIC config failed: {e}"))?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("valid timeout"),
    ));
    transport.initial_rtt(INITIAL_RTT);
    transport.initial_mtu(INITIAL_MTU);
    if !mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(VarInt::from_u32(0))
        .max_ack_delay(Some(Duration::ZERO))
        .reordering_threshold(VarInt::from_u32(2));
    transport.ack_frequency_config(Some(ack_frequency));
    transport.datagram_receive_buffer_size(Some(65_535));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(256));

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn build_endpoint(local_addr: SocketAddr, client_config: &ClientConfig) -> Result<Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let socket = create_udp_socket(local_addr)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        runtime.wrap_udp_socket(socket)?,
        runtime,
    )?;
    endpoint.set_default_client_config(client_config.clone());
    Ok(endpoint)
}

async fn connect_with_handshake(
    endpoint: &Endpoint,
    client_config: ClientConfig,
    addr: SocketAddr,
) -> Result<Connection> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        endpoint.connect_with(client_config, addr, SERVER_NAME)?,
    )
    .await
    .context("connect timeout")?
    .map_err(Into::into)
}

fn create_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
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
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(10));
        assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SEND_TIMEOUT, Duration::from_millis(100));
        assert_eq!(INITIAL_MTU, 1472);
        assert_eq!(INITIAL_RTT, Duration::from_millis(10));
    }
}
