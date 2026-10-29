//! rustls 服务端/客户端配置。
//!
//! 与 `wist-center/src/infra/tls.rs` 同构：
//! - 服务端：可选要求客户端证书（`allow_unauthenticated` 用于"首次注册还没有证书"的场景）；
//! - 客户端：显式信任锚（不用系统根），可选客户端证书；
//! - 握手后 `peer_leaf_certificate_der` 取叶证书，交给 `identity` 认人。
//!
//! 私钥只支持 PEM 里的**未加密** PKCS#8 / PKCS#1 / SEC1；带口令的私钥（`ENCRYPTED
//! PRIVATE KEY`）读不了 —— 用文件权限（`0600`/`0640`）保护，不要加 passphrase。

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
    use crate::identity::PeerIdentity;
    use rcgen::KeyPair;
    use rustls_pki_types::ServerName;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    struct Fixture {
        dir: std::path::PathBuf,
        ca_pem: String,
        server_cert: std::path::PathBuf,
        server_key: std::path::PathBuf,
        client_cert_pem: String,
        client_key_pem: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn csr(cn: &str) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        (csr, key.serialize_pem())
    }

    fn fixture() -> Fixture {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wist-pki-tls-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        let (ca, ca_pem, _ca_key) = CertificateAuthority::generate("TLS Test CA").expect("ca");

        let (server_csr, server_key_pem) = csr("localhost");
        let server = ca
            .issue_server_certificate(
                &server_csr,
                &["localhost".to_string(), "127.0.0.1".to_string()],
                3600,
            )
            .expect("server cert");

        let (client_csr, client_key_pem) = csr("client-a");
        let client = ca
            .issue_client_certificate(&client_csr, "client-a", 3600)
            .expect("client cert");

        let server_cert = dir.join("server.pem");
        let server_key = dir.join("server.key");
        crate::fs::write_pem(&server_cert, &server.certificate_pem, 0o644).expect("write cert");
        crate::fs::write_pem(&server_key, &server_key_pem, 0o600).expect("write key");

        Fixture {
            dir,
            ca_pem,
            server_cert,
            server_key,
            client_cert_pem: client.certificate_pem,
            client_key_pem,
        }
    }

    /// 起一次握手；返回服务端看到的客户端叶证书（`None` = 没出示）。
    async fn handshake(
        server: ServerConfig,
        client: ClientConfig,
    ) -> Result<Option<Vec<u8>>, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server));
            let (stream, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(peer_leaf_certificate_der(tls.get_ref().1))
        });

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let connector = TlsConnector::from(Arc::new(client));
        let client_result = connector
            .connect(ServerName::try_from("localhost").expect("name"), stream)
            .await;

        let server_result = server_task.await.expect("join");
        match (client_result, server_result) {
            (Ok(_), Ok(leaf)) => Ok(leaf),
            (Err(e), _) => Err(format!("client: {e}")),
            (_, Err(e)) => Err(format!("server: {e}")),
        }
    }

    #[test]
    fn install_crypto_provider_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn server_config_rejects_an_empty_anchor() {
        let f = fixture();
        assert!(server_config_mtls(&f.server_cert, &f.server_key, "", true).is_err());
        assert!(server_config_mtls(&f.server_cert, &f.server_key, "   ", false).is_err());
    }

    #[test]
    fn server_config_accepts_a_valid_pair() {
        let f = fixture();
        assert!(server_config(&f.server_cert, &f.server_key).is_ok());
        assert!(server_config_mtls(&f.server_cert, &f.server_key, &f.ca_pem, false).is_ok());
    }

    #[test]
    fn client_config_rejects_an_empty_anchor() {
        assert!(client_config("", None).is_err());
        assert!(client_config("not a pem", None).is_err());
    }

    #[test]
    fn client_config_rejects_a_bad_identity() {
        let f = fixture();
        assert!(client_config(&f.ca_pem, Some((f.client_cert_pem.as_str(), "not a key"))).is_err());
        assert!(client_config(&f.ca_pem, Some(("not a cert", f.client_key_pem.as_str()))).is_err());
    }

    #[test]
    fn client_config_without_identity_is_fine() {
        let f = fixture();
        assert!(client_config(&f.ca_pem, None).is_ok());
    }

    #[test]
    fn chain_from_pem_rejects_key_only_input() {
        let (_ca, _pem, key) = CertificateAuthority::generate("CA").expect("ca");
        assert!(chain_from_pem(&key).is_err());
        assert!(chain_from_pem("").is_err());
    }

    #[test]
    fn chain_from_pem_keeps_the_order() {
        let (_, first, _) = CertificateAuthority::generate("First").expect("ca");
        let (_, second, _) = CertificateAuthority::generate("Second").expect("ca");
        let chain = chain_from_pem(&format!("{first}\n{second}")).expect("chain");
        assert_eq!(chain.len(), 2);
    }

    #[tokio::test]
    async fn strict_mtls_rejects_a_client_without_certificate() {
        let f = fixture();
        let server =
            server_config_mtls(&f.server_cert, &f.server_key, &f.ca_pem, false).expect("server");
        let client = client_config(&f.ca_pem, None).expect("client");
        assert!(handshake(server, client).await.is_err());
    }

    #[tokio::test]
    async fn optional_mtls_accepts_an_anonymous_client() {
        let f = fixture();
        let server =
            server_config_mtls(&f.server_cert, &f.server_key, &f.ca_pem, true).expect("server");
        let client = client_config(&f.ca_pem, None).expect("client");
        let leaf = handshake(server, client).await.expect("handshake");
        assert!(leaf.is_none(), "anonymous client must not present a leaf");
    }

    #[tokio::test]
    async fn mtls_reports_the_identified_client() {
        let f = fixture();
        let server =
            server_config_mtls(&f.server_cert, &f.server_key, &f.ca_pem, false).expect("server");
        let client = client_config(
            &f.ca_pem,
            Some((f.client_cert_pem.as_str(), f.client_key_pem.as_str())),
        )
        .expect("client");

        let leaf = handshake(server, client)
            .await
            .expect("handshake")
            .expect("client leaf");
        let identity = PeerIdentity::from_certificate_der(&leaf).expect("identity");
        assert_eq!(identity.id, "client-a");
    }

    #[tokio::test]
    async fn a_client_from_another_ca_is_rejected() {
        let f = fixture();
        let server =
            server_config_mtls(&f.server_cert, &f.server_key, &f.ca_pem, false).expect("server");

        // 另一个 CA 签的客户端证书：链验不过，握手失败。
        let (other_ca, _, _) = CertificateAuthority::generate("Other CA").expect("ca");
        let (csr_pem, key_pem) = csr("intruder");
        let other_client = other_ca
            .issue_client_certificate(&csr_pem, "intruder", 3600)
            .expect("issue");
        let client = client_config(
            &f.ca_pem,
            Some((other_client.certificate_pem.as_str(), key_pem.as_str())),
        )
        .expect("client");

        assert!(handshake(server, client).await.is_err());
    }

    #[test]
    fn fixture_cleans_up_its_directory() {
        let dir = {
            let f = fixture();
            assert!(f.dir.exists());
            f.dir.clone()
        };
        assert!(!dir.exists());
    }
}
