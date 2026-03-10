use rustls::{
    DigitallySignedStruct, Error as RustlsError, NamedGroup, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{fmt, sync::Arc};

/// Returns the crypto provider configured for Solana QUIC connections.
///
/// Uses the ring crypto provider with only X25519 key exchange enabled,
/// matching Solana's validator QUIC configuration.
pub fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    // Disable all key exchange algorithms except X25519
    provider
        .kx_groups
        .retain(|kx| kx.name() == NamedGroup::X25519);
    provider
}

/// TLS certificate verifier that skips certificate chain validation but still
/// verifies TLS handshake signatures.
///
/// WARNING: This disables TLS server certificate verification.
///
/// Only use this when the remote peer identity is validated out-of-band
/// (e.g., via Solana's leader schedule). Otherwise this enables MITM attacks.
///
/// TLS 1.2/1.3 handshake signatures are still verified. Solana validators
/// expect proper TLS protocol compliance — skipping signature verification
/// causes validators to close connections after handshake completion.
pub struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(crypto_provider())))
    }
}

impl Default for SkipServerVerification {
    fn default() -> Self {
        Self(Arc::new(crypto_provider()))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        // Skip certificate chain validation - peer identity is verified out-of-band
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        // CRITICAL: Must verify TLS signatures for proper protocol compliance
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
        // CRITICAL: Must verify TLS signatures for proper protocol compliance
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
}

impl fmt::Debug for SkipServerVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkipServerVerification")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_provider_only_enables_x25519() {
        let provider = crypto_provider();

        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519);
    }

    #[test]
    fn crypto_provider_has_signature_algorithms() {
        let provider = crypto_provider();

        assert!(
            !provider
                .signature_verification_algorithms
                .supported_schemes()
                .is_empty()
        );
    }

    #[test]
    fn skip_server_verification_new_returns_arc() {
        let verifier = SkipServerVerification::new();

        assert_eq!(Arc::strong_count(&verifier), 1);
    }

    #[test]
    fn skip_server_verification_default_trait() {
        let verifier = SkipServerVerification::default();

        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn skip_server_verification_supported_schemes() {
        let verifier = SkipServerVerification::new();

        let schemes = verifier.supported_verify_schemes();

        assert!(!schemes.is_empty());
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }

    #[test]
    fn skip_server_verification_verify_server_cert_always_succeeds() {
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

        let verifier = SkipServerVerification::new();

        let cert = CertificateDer::from(vec![0u8; 32]);
        let server_name = ServerName::try_from("test.example.com").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);

        assert!(result.is_ok());
    }

    #[test]
    fn skip_server_verification_debug_impl() {
        let verifier = SkipServerVerification::new();

        let debug_str = format!("{:?}", verifier);

        assert!(debug_str.contains("SkipServerVerification"));
    }
}
