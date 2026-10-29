//! 从**已验证**的客户端叶证书还原身份。
//!
//! 与 `wist-center/src/infra/gateway_ca.rs` 同口径：权威身份是 URI SAN
//! `wist://gateway/<id>`；没有 URI SAN 时退到 `CN`（便于非网关组件复用同一套 CA）。

use ring::digest::{SHA256, digest};
use serde::Serialize;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// URI SAN 前缀：`wist://gateway/<id>`。
pub const GATEWAY_URI_PREFIX: &str = "wist://gateway/";

pub fn gateway_uri(identity: &str) -> String {
    format!("{GATEWAY_URI_PREFIX}{identity}")
}

pub fn gateway_id_from_uri(uri: &str) -> Option<String> {
    uri.strip_prefix(GATEWAY_URI_PREFIX)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

/// 握手期已被 CA 验过链的客户端身份。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerIdentity {
    /// 权威身份（URI SAN → `id`；否则 `CN`）。
    pub id: String,
    /// 命中的 URI SAN（若来自 URI）。
    pub uri: Option<String>,
    /// 证书 CN（人类可读标签；已裁剪两端空白，空白 CN 视为缺失）。
    pub cn: Option<String>,
    /// 证书 DER 的 SHA-256（小写 hex）。
    pub fingerprint_sha256: String,
    /// 序列号（小写 hex，无分隔符）。
    pub serial_hex: String,
    /// RFC3339。
    pub not_before: String,
    /// RFC3339。
    pub not_after: String,
}

impl PeerIdentity {
    pub fn from_certificate_der(certificate_der: &[u8]) -> Result<Self, String> {
        let (_, certificate) = X509Certificate::from_der(certificate_der)
            .map_err(|err| format!("failed to parse client certificate: {err}"))?;

        // CN 仅作人类可读标签：裁剪空白；全空白的 CN 视为缺失（否则会得到一个 "" 身份）。
        let cn = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        // 只认 `wist://gateway/<id>` 这一种 URI SAN；其他 URI（spiffe:// 等）忽略。
        let mut uri = None;
        if let Ok(Some(san)) = certificate.subject_alternative_name() {
            for name in &san.value.general_names {
                if let GeneralName::URI(value) = name
                    && gateway_id_from_uri(value).is_some()
                {
                    uri = Some(value.to_string());
                    break;
                }
            }
        }

        let id = uri
            .as_deref()
            .and_then(gateway_id_from_uri)
            .or_else(|| cn.clone())
            .ok_or_else(|| {
                "client certificate has neither a gateway URI SAN nor a CN".to_string()
            })?;

        let validity = certificate.validity();
        Ok(Self {
            id,
            uri,
            cn,
            fingerprint_sha256: crate::ca::hex_lower(digest(&SHA256, certificate_der).as_ref()),
            serial_hex: crate::ca::hex_lower(certificate.raw_serial()),
            not_before: rfc3339(validity.not_before.timestamp()),
            not_after: rfc3339(validity.not_after.timestamp()),
        })
    }
}

fn rfc3339(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| seconds.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn cert(cn: Option<&str>, uris: &[&str]) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        // rcgen 默认会塞一个 CN（"rcgen self signed cert"）：这里显式清空，
        // 才能构造“没有 CN”的证书。
        params.distinguished_name = DistinguishedName::new();
        if let Some(value) = cn {
            params
                .distinguished_name
                .push(DnType::CommonName, value.to_string());
        }
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI(uri.to_string().try_into().expect("ia5")))
            .collect();
        params.self_signed(&key).expect("cert").der().to_vec()
    }

    #[test]
    fn uri_round_trip() {
        assert_eq!(
            gateway_id_from_uri(&gateway_uri("gw-1")).as_deref(),
            Some("gw-1")
        );
        assert_eq!(gateway_id_from_uri("wist://gateway/"), None);
        assert_eq!(gateway_id_from_uri("https://example.com"), None);
        assert_eq!(gateway_id_from_uri(""), None);
    }

    #[test]
    fn uri_identity_wins_over_cn() {
        let id =
            PeerIdentity::from_certificate_der(&cert(Some("cn-label"), &["wist://gateway/uri-id"]))
                .expect("identity");
        assert_eq!(id.id, "uri-id");
        assert_eq!(id.uri.as_deref(), Some("wist://gateway/uri-id"));
        assert_eq!(id.cn.as_deref(), Some("cn-label"));
    }

    #[test]
    fn non_gateway_uri_falls_back_to_cn() {
        let id = PeerIdentity::from_certificate_der(&cert(
            Some("cn-label"),
            &["spiffe://example.org/workload"],
        ))
        .expect("identity");
        assert_eq!(id.id, "cn-label");
        assert_eq!(id.uri, None);
    }

    #[test]
    fn empty_gateway_id_falls_back_to_cn() {
        let id = PeerIdentity::from_certificate_der(&cert(Some("cn-label"), &["wist://gateway/"]))
            .expect("identity");
        assert_eq!(id.id, "cn-label");
        assert_eq!(id.uri, None);
    }

    #[test]
    fn picks_the_first_gateway_uri() {
        let id = PeerIdentity::from_certificate_der(&cert(
            None,
            &["wist://gateway/first", "wist://gateway/second"],
        ))
        .expect("identity");
        assert_eq!(id.id, "first");
    }

    #[test]
    fn missing_uri_and_cn_is_an_error() {
        let err = PeerIdentity::from_certificate_der(&cert(None, &[])).unwrap_err();
        assert!(err.contains("neither"), "unexpected error: {err}");
    }

    #[test]
    fn blank_cn_is_treated_as_missing() {
        let id = PeerIdentity::from_certificate_der(&cert(Some("   "), &["wist://gateway/uri-id"]))
            .expect("identity");
        assert_eq!(id.id, "uri-id");
        assert_eq!(id.cn, None);

        // 只有空白 CN、没有可用 URI → 仍然报错，而不是返回空身份。
        assert!(PeerIdentity::from_certificate_der(&cert(Some("   "), &[])).is_err());
    }

    #[test]
    fn cn_is_trimmed() {
        let id =
            PeerIdentity::from_certificate_der(&cert(Some("  padded  "), &[])).expect("identity");
        assert_eq!(id.id, "padded");
        assert_eq!(id.cn.as_deref(), Some("padded"));
    }

    #[test]
    fn slash_in_uri_identity_is_preserved_by_the_parser() {
        // 签发侧（ca.rs）会拒绝这种 identity；解析侧保持"如实反映证书内容"，
        // 便于排障时看出对端到底出示了什么。
        let id = PeerIdentity::from_certificate_der(&cert(None, &["wist://gateway/a/b"]))
            .expect("identity");
        assert_eq!(id.id, "a/b");
    }

    #[test]
    fn reports_fingerprint_serial_and_validity() {
        let der = cert(Some("id"), &[]);
        let id = PeerIdentity::from_certificate_der(&der).expect("identity");
        assert_eq!(
            id.fingerprint_sha256,
            crate::ca::hex_lower(digest(&SHA256, &der).as_ref())
        );
        assert!(!id.serial_hex.is_empty());
        assert!(id.not_before.contains('T'));
        assert!(id.not_after.contains('T'));
        assert!(id.not_after > id.not_before);
    }

    #[test]
    fn invalid_der_is_an_error() {
        assert!(PeerIdentity::from_certificate_der(b"not a certificate").is_err());
        assert!(PeerIdentity::from_certificate_der(&[]).is_err());
    }
}
