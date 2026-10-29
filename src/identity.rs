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
    /// 证书 CN（人类可读标签）。
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

        let cn = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(str::to_string);

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

    #[test]
    fn uri_round_trip() {
        assert_eq!(
            gateway_id_from_uri(&gateway_uri("gw-1")).as_deref(),
            Some("gw-1")
        );
        assert_eq!(gateway_id_from_uri("wist://gateway/"), None);
        assert_eq!(gateway_id_from_uri("https://example.com"), None);
    }
}
