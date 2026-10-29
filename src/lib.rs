//! 从 `wist-center`（CA-G / 服务端 mTLS）和 `wist-gwlinkd`（客户端 keypair / mTLS client）
//! 抽出的可复用 PKI 原语。
//!
//! 三种角色对应同一套口径：
//!
//! - **CA**：`CertificateAuthority`，自签根 + 按 CSR 签叶证书（CSR 只贡献公钥）；
//! - **服务端**：`tls::server_config*`，可要求客户端证书；握手后用 `identity` 认人；
//! - **客户端**：`tls::client_config*`，显式信任锚 + 客户端证书。
//!
//! 与 center/gwlinkd 保持一致的细节：`notBefore` 回拨 300s 容忍时钟偏差、
//! 客户端证书 `EKU=clientAuth` + URI SAN `wist://gateway/<id>`、CA 私钥 `0600`、证书 `0644`。

pub mod ca;
pub mod fs;
pub mod identity;
pub mod inspect;
pub mod tls;

pub use ca::{CertificateAuthority, IssuedCertificate, CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS};
pub use identity::{GATEWAY_URI_PREFIX, PeerIdentity, gateway_id_from_uri, gateway_uri};
pub use inspect::CertInfo;
