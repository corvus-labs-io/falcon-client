//! Rust client library for submitting Solana transactions to Falcon via QUIC.
//!
//! # Quick Start
//!
//! ```no_run
//! use falcon_client::FalconClient;
//! use solana_transaction::versioned::VersionedTransaction;
//! use uuid::Uuid;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let api_key = Uuid::parse_str("your-api-key-here")?;
//! let client = FalconClient::connect("fra.falcon.wtf:5000", api_key).await?;
//!
//! let transaction: VersionedTransaction = todo!();
//! client.send_transaction(&transaction).await?;
//! # Ok(())
//! # }
//! ```

mod tls;

use {
    anyhow::{Context, Result, anyhow},
    arc_swap::ArcSwap,
    tls::{SkipServerVerification, crypto_provider},
    quinn::{
        ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig,
        crypto::rustls::QuicClientConfig,
    },
    rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair},
    solana_transaction::versioned::VersionedTransaction,
    std::{net::SocketAddr, sync::Arc, time::Duration},
    tokio::sync::Mutex,
    tracing::warn,
    uuid::Uuid,
};

const ALPN_FALCON_TX: &[u8] = b"falcon-tx";
const SERVER_NAME: &str = "falcon";
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_millis(200);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
/// Opens a persistent QUIC connection authenticated via mTLS — the API key
/// is embedded in a self-signed client certificate. If the connection drops,
/// sends automatically reconnect before retrying.
pub struct FalconClient {
    endpoint: Endpoint,
    client_config: ClientConfig,
    addr: SocketAddr,
    connection: ArcSwap<Connection>,
    reconnect: Mutex<()>,
}

impl FalconClient {
    /// Opens a QUIC connection to Falcon.
    ///
    /// Resolves `endpoint_addr` via DNS, generates a self-signed client
    /// certificate with `api_key` as the Common Name, and establishes the
    /// QUIC session. Times out after 5 seconds.
    pub async fn connect(endpoint_addr: &str, api_key: Uuid) -> Result<Self> {
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

        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
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
        })
    }

    /// Serializes and sends a transaction to Falcon.
    ///
    /// The transaction is bincode-encoded and written to a new unidirectional
    /// QUIC stream. If the first attempt fails, the connection is
    /// re-established and the send is retried once.
    pub async fn send_transaction(&self, transaction: &VersionedTransaction) -> Result<()> {
        let payload = bincode::serialize(transaction)?;

        let connection = self.connection.load_full();
        if Self::try_send(&connection, &payload).await.is_ok() {
            return Ok(());
        }

        warn!("send failed, reconnecting");
        self.reconnect(true).await?;

        let connection = self.connection.load_full();
        Self::try_send(&connection, &payload).await
    }

    async fn try_send(connection: &Connection, payload: &[u8]) -> Result<()> {
        let mut stream = tokio::time::timeout(OPEN_STREAM_TIMEOUT, connection.open_uni())
            .await
            .context("open_uni timeout")??;

        tokio::time::timeout(WRITE_TIMEOUT, async {
            stream.write_all(payload).await?;
            stream.finish()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("write timeout")??;

        Ok(())
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
    fn constants_have_expected_values() {
        assert_eq!(ALPN_FALCON_TX, b"falcon-tx");
        assert_eq!(SERVER_NAME, "falcon");
        assert_eq!(KEEP_ALIVE_INTERVAL, Duration::from_secs(25));
        assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(OPEN_STREAM_TIMEOUT, Duration::from_millis(200));
        assert_eq!(WRITE_TIMEOUT, Duration::from_millis(500));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
    }
}
