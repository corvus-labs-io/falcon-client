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
/// IMPORTANT: Unlike a complete no-verify implementation, this still verifies
/// TLS 1.2/1.3 handshake signatures. This is required because Solana validators
/// expect proper TLS protocol compliance - skipping signature verification
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
