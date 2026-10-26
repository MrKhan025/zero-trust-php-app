# Security Policy & Threat Model (`SECURITY.md`)

## 1. Architectural Philosophy: Honest Zero-Trust Engineering

No system connected to a network should ever rely on security through obscurity or single-perimeter trust. `zero-trust-php-app` is engineered around **NIST SP 800-207 Zero-Trust Principles** and **Defense-in-Depth**:

- **Assume Breach**: Every component is designed assuming an attacker may already have network visibility, a stolen session cookie, or a read-only database snapshot.
- **Verify Explicitly**: Every request is authenticated, authorized, and scored against live device and network telemetry before access is granted.
- **Least Privilege & Blast-Radius Containment**: Cryptographic keys are separated by context via `HKDF-SHA256`, PII is encrypted at rest via `XChaCha20-Poly1305` / `AES-256-GCM`, and audit logs are cryptographically hash-chained.

## 2. Threat Model & Countermeasures

| Threat Vector | Attack Scenario | Countermeasure in `zero-trust-php-app` |
| :--- | :--- | :--- |
| **Autonomous AI Agents & Bot Swarms** | LLM-driven agents or headless browsers attempt high-velocity credential stuffing or account enumeration. | Stateless HMAC-signed **SHA-256 Proof-of-Work (PoW)** puzzle + single-use nonce replay table (`used_nonces`) + hidden semantic honeytrap fields + constant-time dummy Argon2id verification on missing users. |
| **Offline Database Breach / SQL Snapshot Leak** | Attacker obtains a full copy of the SQLite/MySQL database file. | Passwords use **HMAC-SHA256 Peppering** (secret kept in environment/KMS outside DB) + **Argon2id** (`m=64MB, t=4, p=2`). User emails and TOTP secrets are encrypted with **XChaCha20-Poly1305 AEAD** bound to the user's UUID as Associated Authenticated Data (`AAD`). |
| **Session Hijacking / Cookie Theft** | Attacker steals a valid session token via malware or network interception and replays it from another machine. | Only the blind-indexed hash of the token is stored in the database. Every request compares the live **Device Fingerprint** and **/24 IPv4 (/48 IPv6) Subnet** against the session's bound telemetry; simultaneous drift triggers a risk score $\ge 75$ and immediately revokes the session. |
| **TOTP Code Interception / Replay** | Attacker intercepts a 6-digit TOTP code via real-time phishing and attempts to reuse it within the 30-second window. | Consumed TOTP codes are immediately recorded in `used_nonces` keyed by `user_uuid + time_slice + code`, blocking any second use within the validity window. |
| **Forensic Log Tampering** | Compromised administrator attempts to delete or alter incriminating failed login or WAF events in the database. | Every row in `audit_ledger` includes `prev_hash` and `entry_hash = HMAC-SHA256(prev_hash | fields)` plus AEAD-authenticated context. Any deletion, insertion, or modification breaks `AuditLedger::verifyChainIntegrity()`. |
| **Injection & Cross-Site Scripting (XSS)** | Attacker injects SQL fragments, `<script>` tags, or serialized PHP objects. | Emulated PDO prepares are disabled (`PDO::ATTR_EMULATE_PREPARES => false`), `WafMiddleware` blocks exploit signatures at the perimeter, and responses enforce a per-request 128-bit cryptographic **CSP Nonce**. |

## 3. Cryptographic Primitives Specification

- **Symmetric Authenticated Encryption**: `libsodium` `crypto_aead_xchacha20poly1305_ietf` (256-bit key, 192-bit CSPRNG nonce, 128-bit Poly1305 MAC) or OpenSSL `aes-256-gcm` (256-bit key, 96-bit CSPRNG IV, 128-bit authentication tag).
- **Key Derivation Function**: `HKDF-SHA256` (RFC 5869) with domain-separated `info` strings.
- **Password Hashing**: `HMAC-SHA256(password, ZT_AUTH_PEPPER_SECRET)` $ightarrow$ `Argon2id` (`memory_cost = 65536 KiB`, `time_cost = 4`, `threads = 2`).
- **Message Authentication & Blind Indexing**: `HMAC-SHA256` verified exclusively via constant-time `hash_equals()`.

## 4. Reporting a Vulnerability

If you discover a security vulnerability in this repository:
1. **Do not open a public GitHub issue.**
2. Provide a minimal Proof-of-Concept (PoC) and affected component path to the security maintainers.
3. Run `php tests/SecurityTest.php` and `php bin/verify-ledger.php` to include diagnostic output with your report.
