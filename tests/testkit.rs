use {
    quinn::{Endpoint, crypto::rustls::QuicServerConfig},
    rand::Rng,
    rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair},
    rustls::{
        DigitallySignedStruct, Error as RustlsError, NamedGroup, SignatureScheme,
        client::danger::HandshakeSignatureValid,
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, UnixTime},
    },
    std::{
        net::{SocketAddr, TcpListener},
        sync::Arc,
    },
};

const ALPN_FALCON_TX: &[u8] = b"falcon-tx";

pub fn find_available_port() -> Option<u16> {
    let mut rng = rand::rng();

    for _ in 0..100 {
        let (begin, end) = (32768, 60999);
        let port = rng.random_range(begin..=end);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        if TcpListener::bind(addr).is_ok() {
            return Some(port);
        }
    }

    None
}

pub fn generate_random_local_addr() -> SocketAddr {
    let port = find_available_port().expect("port");
    SocketAddr::new("127.0.0.1".parse().expect("ipv4"), port)
}

fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .kx_groups
        .retain(|kx| kx.name() == NamedGroup::X25519);
    provider
}

fn generate_server_cert() -> (
    CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair generation failed");

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "falcon-test-server");

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);

    let cert = params
        .self_signed(&key_pair)
        .expect("cert generation failed");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .expect("key serialization failed");

    (cert_der, key_der)
}

struct SkipClientVerification(Arc<CryptoProvider>);

impl SkipClientVerification {
    fn new_verifier() -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
        Arc::new(Self(Arc::new(crypto_provider())))
    }
}

impl std::fmt::Debug for SkipClientVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkipClientVerification")
            .finish_non_exhaustive()
    }
}

impl rustls::server::danger::ClientCertVerifier for SkipClientVerification {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, RustlsError> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

pub fn build_mock_falcon_server(addr: SocketAddr) -> Endpoint {
    let (cert, key) = generate_server_cert();
    let provider = crypto_provider();

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_client_cert_verifier(SkipClientVerification::new_verifier())
        .with_single_cert(vec![cert], key)
        .expect("server config");
    server_crypto.alpn_protocols = vec![ALPN_FALCON_TX.to_vec()];

    let quic_crypto = QuicServerConfig::try_from(server_crypto).expect("quic server config");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport
        .max_idle_timeout(quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).ok());
    transport.datagram_receive_buffer_size(Some(2_097_152));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(2));
    server_config.transport_config(Arc::new(transport));

    Endpoint::server(server_config, addr).expect("server endpoint")
}
