//! rustls 服务端/客户端配置。
//!
//! 与 `wist-center/src/infra/tls.rs` 同构：
//! - 服务端：可选要求客户端证书（`allow_unauthenticated` 用于"首次注册还没有证书"的场景）；
//! - 客户端：显式信任锚（不用系统根），可选客户端证书；
//! - 握手后 `peer_leaf_certificate_der` 取叶证书，交给 `identity` 认人。

use std::path::Path;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// 安装 ring provider（幂等）。所有入口都先调它，避免 "no process-level CryptoProvider"。
pub fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 只出示服务端证书，**不校客户端证书**。
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, String> {
    install_crypto_provider();
    let certs = chain_from_file(cert_path)?;
    let key = key_from_file(key_path)?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

/// 服务端 mTLS：以 `client_ca_pem` 为客户端信任锚。
///
/// `allow_unauthenticated = true` 表示"可以不出示证书"（center 用于首次注册）；
/// 出示了就必须验过。默认应传 `false`（严格）。
pub fn server_config_mtls(
    cert_path: &Path,
    key_path: &Path,
    client_ca_pem: &str,
    allow_unauthenticated: bool,
) -> Result<ServerConfig, String> {
    install_crypto_provider();
    let certs = chain_from_file(cert_path)?;
    let key = key_from_file(key_path)?;

    let mut roots = RootCertStore::empty();
    for anchor in CertificateDer::pem_slice_iter(client_ca_pem.as_bytes()) {
        let anchor = anchor.map_err(|err| format!("invalid client CA PEM: {err}"))?;
        roots
            .add(anchor)
            .map_err(|err| format!("failed to add client CA trust anchor: {err}"))?;
    }
    if roots.is_empty() {
        return Err("client CA PEM contains no CERTIFICATE block".to_string());
    }

    let builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
    let verifier = if allow_unauthenticated {
        builder.allow_unauthenticated()
    } else {
        builder
    }
    .build()
    .map_err(|err| format!("failed to build client certificate verifier: {err}"))?;

    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

/// 客户端配置：显式信任锚 + 可选客户端证书（PEM 文本）。
pub fn client_config(ca_pem: &str, identity: Option<(&str, &str)>) -> Result<ClientConfig, String> {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    for anchor in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let anchor = anchor.map_err(|err| format!("invalid CA PEM: {err}"))?;
        roots
            .add(anchor)
            .map_err(|err| format!("failed to add CA trust anchor: {err}"))?;
    }
    if roots.is_empty() {
        return Err("CA PEM contains no CERTIFICATE block".to_string());
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);
    match identity {
        Some((cert_pem, key_pem)) => {
            let certs = chain_from_pem(cert_pem)?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|err| format!("invalid client private key: {err}"))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|err| format!("invalid client certificate or key: {err}"))
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

/// 客户端配置：信任锚与身份都从文件读。
pub fn client_config_from_files(
    ca_path: &Path,
    identity: Option<(&Path, &Path)>,
) -> Result<ClientConfig, String> {
    let ca_pem = std::fs::read_to_string(ca_path)
        .map_err(|err| format!("failed to read CA {}: {err}", ca_path.display()))?;
    match identity {
        Some((cert_path, key_path)) => {
            let cert_pem = std::fs::read_to_string(cert_path).map_err(|err| {
                format!("failed to read client cert {}: {err}", cert_path.display())
            })?;
            let key_pem = std::fs::read_to_string(key_path).map_err(|err| {
                format!("failed to read client key {}: {err}", key_path.display())
            })?;
            client_config(&ca_pem, Some((&cert_pem, &key_pem)))
        }
        None => client_config(&ca_pem, None),
    }
}

/// 从**已完成握手**的服务端连接里取客户端叶证书 DER。
pub fn peer_leaf_certificate_der(conn: &rustls::server::ServerConnection) -> Option<Vec<u8>> {
    conn.peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| leaf.as_ref().to_vec())
}

pub fn chain_from_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read TLS certificate {}: {err}", path.display()))?;
    chain_from_pem(&pem)
}

pub fn chain_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|err| format!("invalid TLS certificate PEM: {err}"))?;
    if certs.is_empty() {
        return Err("TLS certificate PEM contains no CERTIFICATE block".to_string());
    }
    Ok(certs)
}

fn key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|err| format!("invalid TLS private key {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;

    #[test]
    fn mtls_server_config_rejects_an_empty_anchor() {
        let (ca, ca_pem, ca_key) = CertificateAuthority::generate("Test CA").expect("ca");
        let _ = ca;
        let dir = std::env::temp_dir().join(format!("wist-pki-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let cert = dir.join("server.pem");
        let key = dir.join("server.key");
        crate::fs::write_pem(&cert, &ca_pem, 0o644).expect("cert");
        crate::fs::write_pem(&key, &ca_key, 0o600).expect("key");

        assert!(server_config_mtls(&cert, &key, "", true).is_err());
        assert!(server_config(&cert, &key).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
