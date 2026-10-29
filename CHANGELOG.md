# Changelog

## [0.1.0] - 2026-10-29

### Added

- 从 `wist-center`（`infra/gateway_ca.rs`、`infra/tls.rs`）与 `wist-gwlinkd`（`identity.rs`）抽出：
  - `CertificateAuthority`：自签 CA、按 CSR 签客户端/服务端证书（URI SAN / DNS SAN、EKU 限定、序列号与指纹）；
  - `tls`：服务端（严格/可选客户端证书）、客户端（显式信任锚 + 客户端证书）、握手后取叶证书；
  - `PeerIdentity`：从已验证叶证书还原身份（URI SAN 优先，退化 CN），含指纹/序列号/有效期；
  - `inspect`：PEM 检查（取代 doctor 对 `openssl` 子进程的依赖）；
  - `fs`：`tmp → chmod → rename` 原子写。
