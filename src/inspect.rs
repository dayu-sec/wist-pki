//! PEM 检查：主语、有效期、序列号、SHA-256 指纹。
//!
//! 用来替代 doctor 里对 `openssl` 子进程的依赖 —— 容器里不一定装 openssl。

use std::path::Path;

use serde::Serialize;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_hex: String,
    /// 证书 DER 的 SHA-256（小写 hex）。
    pub sha256: String,
    pub is_ca: bool,
}

pub fn inspect_pem_file(path: &Path) -> Result<CertInfo, String> {
    let pem = crate::fs::read_pem(path)?;
    inspect_pem(&pem)
}

/// 检查 PEM 里的**第一张**证书（私钥块会被跳过）。
pub fn inspect_pem(pem_text: &str) -> Result<CertInfo, String> {
    let der = first_certificate_der(pem_text)?;
    let (_, certificate) = X509Certificate::from_der(&der)
        .map_err(|err| format!("failed to parse certificate: {err}"))?;
    let validity = certificate.validity();
    Ok(CertInfo {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_before: rfc3339(validity.not_before.timestamp()),
        not_after: rfc3339(validity.not_after.timestamp()),
        serial_hex: crate::ca::hex_lower(certificate.raw_serial()),
        sha256: crate::ca::hex_lower(ring::digest::digest(&ring::digest::SHA256, &der).as_ref()),
        is_ca: certificate.is_ca(),
    })
}

/// 取 PEM 里的第一张证书 DER（忽略私钥块）。
pub fn first_certificate_der(pem_text: &str) -> Result<Vec<u8>, String> {
    for block in pem::parse_many(pem_text).map_err(|err| format!("invalid PEM: {err}"))? {
        if block.tag() == "CERTIFICATE" {
            return Ok(block.contents().to_vec());
        }
    }
    Err("no CERTIFICATE block found".to_string())
}

fn rfc3339(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| seconds.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;

    fn ca() -> (CertificateAuthority, String, String) {
        CertificateAuthority::generate("Inspect Test CA").expect("ca")
    }

    #[test]
    fn rejects_a_key_without_certificate() {
        let (_, _c, key) = ca();
        assert!(inspect_pem(&key).is_err());
    }

    #[test]
    fn inspects_a_ca_certificate() {
        let (_, pem, _key) = ca();
        let info = inspect_pem(&pem).expect("inspect");
        assert!(info.is_ca);
        assert!(info.subject.contains("Inspect Test CA"), "{}", info.subject);
        assert_eq!(info.subject, info.issuer);
        assert_eq!(info.sha256.len(), 64);
        assert!(!info.serial_hex.is_empty());
        assert!(info.not_before < info.not_after);
    }

    #[test]
    fn inspects_a_leaf_as_non_ca() {
        let (ca, _pem, _key) = ca();
        let key = rcgen::KeyPair::generate().expect("key");
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = ca
            .issue_server_certificate(&csr, &["svc.example.com".to_string()], 60)
            .expect("issue");
        let info = inspect_pem(&issued.certificate_pem).expect("inspect");
        assert!(!info.is_ca);
        assert_eq!(info.sha256, issued.fingerprint_sha256_hex);
    }

    #[test]
    fn picks_the_first_certificate_from_a_chain() {
        let (_, first_pem, _) = ca();
        let (_, second_pem, _) = ca();
        let chain = format!("{first_pem}\n{second_pem}\n");
        let info = inspect_pem(&chain).expect("inspect");
        assert_eq!(info.sha256, inspect_pem(&first_pem).expect("first").sha256);
        assert_ne!(
            info.sha256,
            inspect_pem(&second_pem).expect("second").sha256
        );
    }

    #[test]
    fn ignores_private_key_blocks() {
        let (_, cert_pem, key_pem) = ca();
        let combined = format!("{key_pem}\n{cert_pem}");
        let info = inspect_pem(&combined).expect("inspect");
        assert!(info.is_ca);
        assert_eq!(info.sha256, inspect_pem(&cert_pem).expect("cert").sha256);
    }

    #[test]
    fn missing_file_reports_the_path() {
        let path = std::env::temp_dir().join("wist-pki-does-not-exist.pem");
        let err = inspect_pem_file(&path).unwrap_err();
        assert!(err.contains("wist-pki-does-not-exist"), "unexpected: {err}");
    }

    #[test]
    fn invalid_pem_and_empty_input_are_errors() {
        assert!(inspect_pem("not a pem").is_err());
        assert!(inspect_pem("").is_err());
        assert!(first_certificate_der("").is_err());
        assert!(
            first_certificate_der("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
                .is_err()
        );
    }
}
