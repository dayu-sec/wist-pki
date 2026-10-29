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

    #[test]
    fn rejects_a_key_without_certificate() {
        let (_, _c, key) = crate::ca::CertificateAuthority::generate("CA").expect("ca");
        assert!(inspect_pem(&key).is_err());
    }
}
