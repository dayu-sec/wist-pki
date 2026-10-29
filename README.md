# wist-pki

从 `wist-center`（CA-G 签发 / 服务端 mTLS）与 `wist-gwlinkd`（客户端 keypair / mTLS client）抽出的
可复用 PKI 原语，供 `wist-ingest-ctrl` / `wist-ingest-web` 这类"中心 ↔ 站点"链路共用。

## 三种角色

| 角色 | API | 说明 |
|---|---|---|
| CA | `CertificateAuthority::{generate,load,load_or_create}` | 自签根 + 按 CSR 签叶证书；**CSR 只贡献公钥** |
| 签发 | `issue_client_certificate(csr, identity, ttl)` / `issue_server_certificate(csr, dns, ttl)` | 客户端证书带 `EKU=clientAuth` + URI SAN `wist://gateway/<id>`；服务端证书带 `EKU=serverAuth` + DNS SAN |
| 服务端 | `tls::server_config` / `tls::server_config_mtls(ca, allow_unauthenticated)` | 可要求客户端证书；`allow_unauthenticated` 对应 center 的"首次注册还没有证书" |
| 客户端 | `tls::client_config(ca_pem, Some((cert,key)))` / `client_config_from_files` | 显式信任锚（不用系统根）+ 可选客户端证书 |
| 认人 | `PeerIdentity::from_certificate_der` / `tls::peer_leaf_certificate_der` | URI SAN 优先，退化到 CN；同时给出指纹 / 序列号 / 有效期 |
| 检查 | `inspect::inspect_pem_file` | 主语 / 有效期 / 序列号 / SHA-256 / 是否 CA（不依赖 `openssl` 二进制） |

## 与 center/gwlinkd 一致的口径

- `notBefore` 回拨 `300s`（`CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS`）；
- 客户端证书 `CN` 只是人类可读标签，权威身份是 URI SAN `wist://gateway/<id>`；
- CA 证书落盘 `0644`、CA 私钥 `0600`；写入走 `tmp → chmod → rename`；
- CA “半在场”（只有证书或只有私钥）一律报错，不自动重生。

## 更严格的校验（review 后加的）

| 检查 | 行为 |
|---|---|
| CA 私钥与证书公钥不匹配 | `from_pem` 直接报错（否则签出的证书永远验不过链，且错得很晚） |
| 客户端 identity | 非空、≤ 256 字节、不允许空白/控制字符与 `/ \\ ? # %` |
| 服务端 DNS SAN | 非空、≤ 253 字节、不允许空白/控制字符（通配符允许） |
| TTL | `1..=10 年`（防止 `now + ttl` 溢出与“事实永久”） |
| CN 空白 | 解析时裁剪；全空白视为无 CN，退到 URI SAN |
| 临时文件 | 文件名带 `pid + 序号`，失败时自动清理 |

## 迁移说明

`wist-center/src/infra/{gateway_ca,tls}.rs`、`wist-gwlinkd/src/identity.rs` 可作为对照；
后续可改为依赖本 crate，删除重复实现（本仓先不动那两个服务）。

## 测试

```bash
cargo test      # 55 个用例
```

覆盖：CA 生成/加载/错配拒绝、CSR 只贡献公钥、客户端/服务端 SAN 与 EKU、TTL 边界、
identity 与 DNS 名校验、身份解析（URI 优先/非网关 URI/空 URI/空白 CN/无效 DER）、
PEM 检查（链取首张/私钥块跳过）、原子写（权限/覆盖/并发/无残留）、
以及**真握手**：严格 mTLS 拒绝无证书、可选 mTLS 接受匿名、跨 CA 拒绝、身份回收。
