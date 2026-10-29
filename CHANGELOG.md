# Changelog

## [0.1.1] - 2026-10-29

### Fixed（5 轮 review 发现）

- **CA 私钥与证书不匹配时静默签发**：rcgen 只用私钥、证书仅作 issuer 句柄，错配会产出永远验不过链的叶证书。
  现在 `from_pem` 比对 SPKI，不匹配直接报错。
- **TTL 无上限**：`i64::MAX` 会让 `now + ttl` 溢出。现在限制在 `1..=10 年`。
- **identity / DNS SAN 无校验**：可签出 `wist://gateway/a/b`、含空白/控制字符的 identity 或空 DNS SAN。
  现在签发前校验（长度上限、字符集、通配符仍允许）。
- **临时文件重名**：`write_pem` 只带 pid，同进程并发写同一路径会互踩；失败时还会遗留 `.tmp.*`。
  现在 `pid + 序号` 且失败自动清理。
- **空白 CN 会产出空身份**：CN 全空白时 `id` 变成 `""`。现在裁剪，全空白视为无 CN。

### Added

- 公共常量：`MAX_TTL_SECONDS` / `MAX_IDENTITY_LEN` / `MAX_DNS_NAME_LEN`。
- 测试从 **6 增加到 55**，包括真 TLS 握手（严格/可选 mTLS、跨 CA 拒绝、身份回收）。

## [0.1.0] - 2026-10-29

### Added

- 从 `wist-center`（`infra/gateway_ca.rs`、`infra/tls.rs`）与 `wist-gwlinkd`（`identity.rs`）抽出：
  - `CertificateAuthority`：自签 CA、按 CSR 签客户端/服务端证书（URI SAN / DNS SAN、EKU 限定、序列号与指纹）；
  - `tls`：服务端（严格/可选客户端证书）、客户端（显式信任锚 + 客户端证书）、握手后取叶证书；
  - `PeerIdentity`：从已验证叶证书还原身份（URI SAN 优先，退化 CN），含指纹/序列号/有效期；
  - `inspect`：PEM 检查（取代 doctor 对 `openssl` 子进程的依赖）；
  - `fs`：`tmp → chmod → rename` 原子写。
