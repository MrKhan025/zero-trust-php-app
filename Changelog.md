# Changelog

All notable changes to **`zerotrust-php`** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0](https://www.google.com/search?q=https://github.com/MrKhan025/zerotrust-php/releases/tag/v1.0.0) - 2026-10-28

### Added
- **Continuous Adaptive Policy Engine** (`ZeroTrustPolicyEngine`) with live risk scoring (`0–100`) across device fingerprints, User-Agent hashes, and `/24` IPv4 (`/48` IPv6) subnets.
- **Authenticated Encryption with Associated Data (AEAD)** (`CryptoEngine`) using `libsodium` XChaCha20-Poly1305-IETF with automatic fallback to OpenSSL AES-256-GCM and HKDF-SHA256 subkey derivation.
- **Peppered Argon2id Password Hashing** with pre-hash HMAC-SHA256 peppering and constant-time dummy verification against username timing enumeration.
- **Multi-Factor Authentication**: Full RFC 6238 TOTP (`TotpAuthenticator`), 8 single-use HMAC recovery codes, and pure-PHP WebAuthn / Passkeys (`WebAuthnService` with CBOR & ES256 COSE verification).
- **Anti-AI & Bot Defense** (`BotDefenseGuard`) with stateless HMAC-signed SHA-256 Proof-of-Work challenges, single-use nonce replay tracking, and WCAG-accessible honeytrap fields.
- **Application-Layer WAF & CSP Nonce Enforcer** (`WafMiddleware`) blocking SQLi, XSS, Path Traversal, Object Deserialization, Command Injection, and Null-Byte payloads.
- **Tamper-Evident Hash-Chained Audit Ledger** (`AuditLedger` & `bin/verify-ledger.php`) with AEAD-encrypted context and HMAC-SHA256 block chaining from Genesis.
- **Pluggable Storage Layer** (`SqliteStorage` with self-healing `kv_store` provisioning and `RedisStorage`).
- **Multi-OS & Multi-PHP CI Matrix** (`.github/workflows/ci.yml` & `codeql.yml`) verifying PHP 8.4, 8.5, and 8.6 across Ubuntu 26.04 LTS, Ubuntu 24.04 LTS, macOS 15 Sequoia, and Windows Server 2025.
- **Community & Governance Suite**: `ACCESSIBILITY.md` (WCAG 2.1 AA), `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, GitHub Issue & PR templates, Dependabot config, `CODEOWNERS`, and RFC 9116 `security.txt`.
