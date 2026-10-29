//! 自签 CA 与叶证书签发。
//!
//! 与 `wist-center/src/infra/gateway_ca.rs` 同口径，去掉了"网关"这个词：
//! 同一套代码可以签网关客户端证书，也可以签 ingest↔web 之间的服务端/客户端证书。

use std::fmt;
use std::path::Path;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::identity::gateway_uri;

/// `notBefore` 回拨（容忍两端时钟偏差）。与 center/gwlinkd 一致。
pub const CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS: i64 = 300;

/// 叶证书 TTL 上限（10 年）：防止 `now + ttl` 溢出，也避免签发"事实永久"的证书。
pub const MAX_TTL_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

/// 身份字符串长度上限（与 URI SAN 的实用长度对齐）。
pub const MAX_IDENTITY_LEN: usize = 256;

/// DNS SAN 长度上限（RFC 1035）。
pub const MAX_DNS_NAME_LEN: usize = 253;

/// 签出的证书。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    /// 序列号（小写 hex，无分隔符）。
    pub serial_hex: String,
    /// 证书 DER 的 SHA-256（小写 hex）。
    pub fingerprint_sha256_hex: String,
    /// RFC3339（已含 `notBefore` 回拨）。
    pub not_before: String,
    /// RFC3339。
    pub not_after: String,
    /// 客户端证书填的 URI SAN（服务端证书为 None）。
    pub subject_uri: Option<String>,
    /// 签发时用的 CN（仅人类可读标签）。
    pub subject_cn: String,
}

/// 自签 CA。私钥只应留在签发方；根可按需下发（客户端需要验服务端时）。
pub struct CertificateAuthority {
    /// 签发句柄：只用它的主体 DN / key-id，**不用它的 DER**。
    issuer: Certificate,
    issuer_key: KeyPair,
    ca_certificate_pem: String,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("ca_certificate_pem_len", &self.ca_certificate_pem.len())
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// 从证书/私钥 PEM 载入。
    ///
    /// **会校验两者是否配对**：rcgen 的签发只用到私钥，证书仅作为 issuer 句柄；
    /// 一旦错配，签出来的叶证书链永远验不过（客户端表现为 unknown issuer），
    /// 所以在载入时就失败，而不是等到握手期。
    pub fn from_pem(ca_certificate_pem: &str, ca_key_pem: &str) -> Result<Self, String> {
        let params = CertificateParams::from_ca_cert_pem(ca_certificate_pem)
            .map_err(|err| format!("failed to parse CA certificate: {err}"))?;
        let issuer_key = KeyPair::from_pem(ca_key_pem)
            .map_err(|err| format!("failed to parse CA private key: {err}"))?;

        let der = crate::inspect::first_certificate_der(ca_certificate_pem)
            .map_err(|err| format!("failed to parse CA certificate: {err}"))?;
        let (_, parsed) = X509Certificate::from_der(&der)
            .map_err(|err| format!("failed to parse CA certificate: {err}"))?;
        if parsed.public_key().raw != issuer_key.public_key_der().as_slice() {
            return Err("CA 私钥与证书公钥不匹配：继续签发会产出无法验链的证书".to_string());
        }

        let issuer = params
            .self_signed(&issuer_key)
            .map_err(|err| format!("failed to load CA as an issuer: {err}"))?;
        Ok(Self {
            issuer,
            issuer_key,
            ca_certificate_pem: ca_certificate_pem.to_string(),
        })
    }

    pub fn load(ca_certificate_path: &Path, ca_key_path: &Path) -> Result<Self, String> {
        let cert = std::fs::read_to_string(ca_certificate_path).map_err(|err| {
            format!(
                "failed to read CA certificate {}: {err}",
                ca_certificate_path.display()
            )
        })?;
        let key = std::fs::read_to_string(ca_key_path).map_err(|err| {
            format!(
                "failed to read CA private key {}: {err}",
                ca_key_path.display()
            )
        })?;
        Self::from_pem(&cert, &key)
    }

    /// 生成一把新的自签 CA；返回 `(实例, 证书 PEM, 私钥 PEM)`。
    pub fn generate(common_name: &str) -> Result<(Self, String, String), String> {
        if common_name.trim().is_empty() {
            return Err("CA common name must not be empty".to_string());
        }
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.to_string());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let key = KeyPair::generate().map_err(|err| format!("failed to generate CA key: {err}"))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|err| format!("failed to self-sign CA: {err}"))?;
        let certificate_pem = certificate.pem();
        let key_pem = key.serialize_pem();
        let ca = Self::from_pem(&certificate_pem, &key_pem)?;
        Ok((ca, certificate_pem, key_pem))
    }

    pub fn ca_certificate_pem(&self) -> &str {
        &self.ca_certificate_pem
    }

    /// 用 CSR 的公钥签一张客户端证书（`EKU=clientAuth`，URI SAN = `wist://gateway/<identity>`）。
    ///
    /// **CSR 只贡献公钥**：其 subject 与扩展一律忽略。
    pub fn issue_client_certificate(
        &self,
        csr_pem: &str,
        identity: &str,
        ttl_seconds: i64,
    ) -> Result<IssuedCertificate, String> {
        validate_identity(identity)?;
        let uri = gateway_uri(identity);
        let san = SanType::URI(
            uri.clone()
                .try_into()
                .map_err(|_| format!("identity URI is not a valid IA5 string: {uri}"))?,
        );
        self.issue(
            csr_pem,
            identity,
            vec![san],
            vec![KeyUsagePurpose::DigitalSignature],
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            ttl_seconds,
        )
        .map(|mut issued| {
            issued.subject_uri = Some(uri);
            issued
        })
    }

    /// 用 CSR 的公钥签一张服务端证书（`EKU=serverAuth`，DNS SAN）。
    ///
    /// 第一个 DNS 名会同时用作 CN（人类可读标签）；通配符 `*.example.com` 允许。
    pub fn issue_server_certificate(
        &self,
        csr_pem: &str,
        dns_names: &[String],
        ttl_seconds: i64,
    ) -> Result<IssuedCertificate, String> {
        let Some(first) = dns_names.first() else {
            return Err("server certificate needs at least one DNS SAN".to_string());
        };
        let mut sans = Vec::with_capacity(dns_names.len());
        for name in dns_names {
            validate_dns_name(name)?;
            sans.push(SanType::DnsName(
                name.clone()
                    .try_into()
                    .map_err(|_| format!("invalid DNS SAN: {name}"))?,
            ));
        }
        self.issue(
            csr_pem,
            first,
            sans,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            ttl_seconds,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        csr_pem: &str,
        common_name: &str,
        subject_alt_names: Vec<SanType>,
        key_usages: Vec<KeyUsagePurpose>,
        extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
        ttl_seconds: i64,
    ) -> Result<IssuedCertificate, String> {
        validate_ttl(ttl_seconds)?;
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|err| format!("failed to parse certificate signing request: {err}"))?;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name.to_string());

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.subject_alt_names = subject_alt_names;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = key_usages;
        params.extended_key_usages = extended_key_usages;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::seconds(CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS);
        params.not_after = now + Duration::seconds(ttl_seconds);
        params.serial_number = Some(SerialNumber::from_slice(&random_serial_bytes()?));
        params.use_authority_key_identifier_extension = true;
        let not_before = params.not_before;
        let not_after = params.not_after;

        let certificate = params
            .signed_by(&csr.public_key, &self.issuer, &self.issuer_key)
            .map_err(|err| format!("failed to sign certificate: {err}"))?;
        let certificate_der = certificate.der().to_vec();
        let (_, parsed) = X509Certificate::from_der(&certificate_der)
            .map_err(|err| format!("failed to re-parse signed certificate: {err}"))?;

        Ok(IssuedCertificate {
            certificate_pem: certificate.pem(),
            fingerprint_sha256_hex: hex_lower(digest(&SHA256, &certificate_der).as_ref()),
            serial_hex: hex_lower(parsed.raw_serial()),
            not_before: rfc3339(not_before),
            not_after: rfc3339(not_after),
            subject_uri: None,
            subject_cn: common_name.to_string(),
            certificate_der,
        })
    }
}

/// 仅**校验 CSR 可解析**（不签发）。
pub fn validate_csr(csr_pem: &str) -> Result<(), String> {
    CertificateSigningRequestParams::from_pem(csr_pem)
        .map(|_| ())
        .map_err(|err| format!("failed to parse certificate signing request: {err}"))
}

/// 从文件载入 CA；两边都缺失则生成一把新的并落盘（证书 `0644` / 私钥 `0600`）。
///
/// **半在场**（只有证书或只有私钥）一律报错：不自动重生，以免换 CA 使已签证书全部失效。
pub fn load_or_create(
    cert_path: &Path,
    key_path: &Path,
    common_name: &str,
) -> Result<CertificateAuthority, String> {
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => CertificateAuthority::load(cert_path, key_path),
        (false, false) => {
            let (ca, cert_pem, key_pem) = CertificateAuthority::generate(common_name)?;
            crate::fs::write_pem(cert_path, &cert_pem, 0o644)?;
            crate::fs::write_pem(key_path, &key_pem, 0o600)?;
            Ok(ca)
        }
        (true, false) | (false, true) => Err(format!(
            "CA 不完整：{} 与 {} 必须同时存在（缺一不自动重生，以免换 CA 使已签证书全部失效）",
            cert_path.display(),
            key_path.display()
        )),
    }
}

fn validate_identity(identity: &str) -> Result<(), String> {
    if identity.is_empty() {
        return Err("client identity must not be empty".to_string());
    }
    if identity.len() > MAX_IDENTITY_LEN {
        return Err(format!(
            "client identity 过长（{} > {MAX_IDENTITY_LEN} 字节）",
            identity.len()
        ));
    }
    if identity
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#' | '%'))
    {
        return Err(format!(
            "client identity 含非法字符（不允许空白、控制字符或 / \\ ? # %）：{identity:?}"
        ));
    }
    Ok(())
}

fn validate_dns_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("DNS SAN must not be empty".to_string());
    }
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(format!(
            "DNS SAN 过长（{} > {MAX_DNS_NAME_LEN} 字节）：{name}",
            name.len()
        ));
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("DNS SAN 含空白或控制字符：{name:?}"));
    }
    Ok(())
}

fn validate_ttl(ttl_seconds: i64) -> Result<(), String> {
    if ttl_seconds <= 0 || ttl_seconds > MAX_TTL_SECONDS {
        return Err(format!(
            "certificate ttl must be in 1..={MAX_TTL_SECONDS} seconds, got {ttl_seconds}"
        ));
    }
    Ok(())
}

fn random_serial_bytes() -> Result<[u8; 16], String> {
    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| "failed to generate certificate serial number".to_string())?;
    // 保证正整数编码（首字节最高位清零）。
    serial[0] &= 0x7f;
    Ok(serial)
}

fn rfc3339(t: OffsetDateTime) -> String {
    chrono::DateTime::from_timestamp(t.unix_timestamp(), 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| t.unix_timestamp().to_string())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerIdentity;
    use x509_parser::prelude::GeneralName;

    fn csr(common_name: &str) -> String {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.to_string());
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    fn ca() -> (CertificateAuthority, String, String) {
        CertificateAuthority::generate("Test CA").expect("ca")
    }

    fn san_uris(issued: &IssuedCertificate) -> Vec<String> {
        let (_, cert) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        let Some(san) = cert.subject_alternative_name().ok().flatten() else {
            return Vec::new();
        };
        san.value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect()
    }

    fn san_dns(issued: &IssuedCertificate) -> Vec<String> {
        let (_, cert) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        let Some(san) = cert.subject_alternative_name().ok().flatten() else {
            return Vec::new();
        };
        san.value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn issues_a_client_certificate_that_parses_back_to_its_identity() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_client_certificate(&csr("ignored-cn"), "ingest-a", 3600)
            .expect("issue");

        let identity =
            PeerIdentity::from_certificate_der(&issued.certificate_der).expect("identity");
        assert_eq!(identity.id, "ingest-a");
        assert_eq!(identity.fingerprint_sha256, issued.fingerprint_sha256_hex);
        assert_eq!(san_uris(&issued), vec!["wist://gateway/ingest-a"]);
    }

    #[test]
    fn csr_subject_is_ignored() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_client_certificate(&csr("attacker-supplied"), "real-id", 600)
            .expect("issue");
        let (_, cert) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, "real-id");
        assert_eq!(issued.subject_cn, "real-id");
    }

    #[test]
    fn issued_certificates_are_not_ca_and_have_a_valid_serial() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_client_certificate(&csr("x"), "id", 60)
            .expect("issue");
        let (_, cert) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        assert!(!cert.is_ca());
        assert_eq!(issued.serial_hex.len() % 2, 0);
        assert!(issued.serial_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(issued.fingerprint_sha256_hex.len(), 64);
    }

    #[test]
    fn not_before_is_skewed_back() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_client_certificate(&csr("x"), "id", 60)
            .expect("issue");
        let (_, cert) = X509Certificate::from_der(&issued.certificate_der).expect("parse");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            cert.validity().not_before.timestamp() <= now - 250,
            "expected ~300s skew"
        );
    }

    #[test]
    fn issues_a_server_certificate_with_dns_san() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_server_certificate(
                &csr("ingest-ctrl"),
                &["ingest-ctrl".to_string(), "alt.example.com".to_string()],
                3600,
            )
            .expect("issue");

        assert_eq!(san_dns(&issued), vec!["ingest-ctrl", "alt.example.com"]);
        assert!(san_uris(&issued).is_empty());
        let info = crate::inspect::inspect_pem(&issued.certificate_pem).expect("inspect");
        assert!(!info.is_ca);
        assert!(info.not_after.contains('T'));
    }

    #[test]
    fn server_certificate_requires_at_least_one_dns_name() {
        let (ca, _pem, _key) = ca();
        assert!(ca.issue_server_certificate(&csr("x"), &[], 60).is_err());
    }

    #[test]
    fn server_certificate_rejects_bad_dns_names() {
        let (ca, _pem, _key) = ca();
        for bad in ["", " ", "has space", "ctrl\u{0}char"] {
            assert!(
                ca.issue_server_certificate(&csr("x"), &[bad.to_string()], 60)
                    .is_err(),
                "accepted {bad:?}"
            );
        }
        let too_long = "a".repeat(MAX_DNS_NAME_LEN + 1);
        assert!(
            ca.issue_server_certificate(&csr("x"), &[too_long], 60)
                .is_err()
        );
    }

    #[test]
    fn wildcard_dns_san_is_allowed() {
        let (ca, _pem, _key) = ca();
        let issued = ca
            .issue_server_certificate(&csr("x"), &["*.example.com".to_string()], 60)
            .expect("issue");
        assert_eq!(san_dns(&issued), vec!["*.example.com"]);
    }

    #[test]
    fn client_identity_is_validated() {
        let (ca, _pem, _key) = ca();
        for bad in ["", "a/b", "a b", "a\tb", "a?b", "a#b", "a%b", "a\\b"] {
            assert!(
                ca.issue_client_certificate(&csr("x"), bad, 60).is_err(),
                "accepted {bad:?}"
            );
        }
        let too_long = "a".repeat(MAX_IDENTITY_LEN + 1);
        assert!(
            ca.issue_client_certificate(&csr("x"), &too_long, 60)
                .is_err()
        );
    }

    #[test]
    fn ttl_must_be_positive_and_bounded() {
        let (ca, _pem, _key) = ca();
        for ttl in [0, -1, i64::MAX, MAX_TTL_SECONDS + 1] {
            assert!(
                ca.issue_client_certificate(&csr("x"), "id", ttl).is_err(),
                "accepted ttl={ttl}"
            );
        }
        assert!(
            ca.issue_client_certificate(&csr("x"), "id", MAX_TTL_SECONDS)
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_mismatched_key_pair() {
        let (_ca_a, cert_a, _key_a) = ca();
        let (_ca_b, _cert_b, key_b) = ca();
        let err = CertificateAuthority::from_pem(&cert_a, &key_b).unwrap_err();
        assert!(err.contains("不匹配"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_the_matching_pair() {
        let (_ca, cert, key) = ca();
        assert!(CertificateAuthority::from_pem(&cert, &key).is_ok());
    }

    #[test]
    fn generate_rejects_an_empty_common_name() {
        assert!(CertificateAuthority::generate("").is_err());
        assert!(CertificateAuthority::generate("   ").is_err());
    }

    #[test]
    fn generated_cas_differ() {
        let (_, cert_a, key_a) = ca();
        let (_, cert_b, key_b) = ca();
        assert_ne!(cert_a, cert_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn validate_csr_accepts_and_rejects() {
        assert!(validate_csr(&csr("x")).is_ok());
        assert!(validate_csr("not a csr").is_err());
    }

    #[test]
    fn load_or_create_generates_then_reuses() {
        let dir = std::env::temp_dir().join(format!("wist-pki-loc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cert = dir.join("sub/ca.pem");
        let key = dir.join("sub/ca.key");

        let first = load_or_create(&cert, &key, "Test CA").expect("create");
        let first_pem = first.ca_certificate_pem().to_string();
        assert!(cert.exists() && key.exists());

        let second = load_or_create(&cert, &key, "Test CA").expect("reload");
        assert_eq!(second.ca_certificate_pem(), first_pem);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_refuses_a_partial_ca_on_disk() {
        let dir = std::env::temp_dir().join(format!("wist-pki-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let cert = dir.join("ca.pem");
        let key = dir.join("ca.key");
        std::fs::write(&cert, "x").expect("write");
        assert!(load_or_create(&cert, &key, "CA").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
