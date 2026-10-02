use anyhow::{Context, Result};
use std::sync::Arc;

pub fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["peerce".to_string()]).context("gen cert")?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    Ok((cert_der, key_der))
}

pub fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    *blake3::hash(cert_der).as_bytes()
}

pub fn fingerprint_hex(cert_der: &[u8]) -> String {
    blake3::hash(cert_der).to_hex().to_string()
}

pub fn server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<quinn::ServerConfig> {
    let chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow::anyhow!("bad key: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_single_cert(chain, key)?;
    cfg.transport_config(Arc::new(super::transport_config()));
    Ok(cfg)
}

#[derive(Debug)]
pub struct FingerprintVerify {
    expected: [u8; 32],
}

impl FingerprintVerify {
    pub fn new(expected: [u8; 32]) -> Arc<Self> {
        Arc::new(Self { expected })
    }

    pub fn matches(&self, cert_der: &[u8]) -> bool {
        fingerprint(cert_der) == self.expected
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerify {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer,
        _inter: &[rustls::pki_types::CertificateDer],
        _name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.matches(end.as_ref()) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub fn client_config_fingerprint(fp: [u8; 32]) -> Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(FingerprintVerify::new(fp))
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    cfg.transport_config(Arc::new(super::transport_config()));
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_roundtrip() {
        let (cert, _) = generate().unwrap();
        let fp = fingerprint(&cert);
        let v = FingerprintVerify { expected: fp };
        assert!(v.matches(&cert));
    }

    #[test]
    fn fp_rejects_other() {
        let (a, _) = generate().unwrap();
        let (b, _) = generate().unwrap();
        let v = FingerprintVerify {
            expected: fingerprint(&a),
        };
        assert!(!v.matches(&b));
    }

    #[test]
    fn fp_hex_stable() {
        let (cert, _) = generate().unwrap();
        assert_eq!(fingerprint_hex(&cert).len(), 64);
    }
}
