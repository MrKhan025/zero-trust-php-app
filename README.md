# ZeroTrust Shield Enterprise (`zero-trust-php-app`)

**Enterprise-Grade Zero-Trust PHP Authentication, Continuous Adaptive Risk Engine & Cryptographic Security Gateway**

`zero-trust-php-app` is a full-stack reference implementation of **NIST SP 800-207 Zero-Trust Architecture (ZTA)** and **OWASP ASVS v4.0 Level 3** security controls in modern PHP 8.2+. Rather than trusting a static session cookie after login, every HTTP request is continuously evaluated against cryptographic device bindings, network subnet telemetry, anti-AI Proof-of-Work (PoW) challenges, memory-hard Argon2id + HMAC-SHA256 peppered credentials, RFC 6238 Multi-Factor Authentication, and a tamper-evident hash-chained audit ledger.

## Security Architecture & Defense-in-Depth Matrix

| Security Layer | Cryptographic / Defense Mechanism | Primary Threat Mitigated | Implementation Module |
| :--- | :--- | :--- | :--- |
| **Authenticated Encryption (AEAD)** | `XChaCha20-Poly1305-IETF` (libsodium 192-bit nonce) with `AES-256-GCM` fallback + mandatory Associated Authenticated Data (`AAD`) binding | Database exfiltration, ciphertext tampering, cross-row context swapping | `src/Crypto/CryptoEngine.php` |
| **Subkey Isolation (KDF)** | `HKDF-SHA256` (RFC 5869) context-separated 256-bit subkeys derived per domain (`user-pii`, `user-mfa`, `audit-ledger`, `blind-index`) | Key reuse vulnerabilities and multi-context cryptographic leakage | `src/Crypto/CryptoEngine.php` |
| **Password & Secret Storage** | Pre-hash `HMAC-SHA256` hardware/environment peppering + `Argon2id` (`m=64MB, t=4, p=2`) + timing-equalized dummy verification | Offline GPU/ASIC hash cracking & timing-based username enumeration | `src/Crypto/CryptoEngine.php` |
| **Searchable Encrypted PII** | Deterministic `HMAC-SHA256` Blind Indexing (`email_hash`) alongside AEAD-encrypted payloads (`email_encrypted`) | Plaintext PII leakage in SQL snapshots and database dumps | `src/Auth/ZeroTrustAuthService.php` |
| **Multi-Factor Authentication** | `RFC 6238 TOTP` (160-bit Base32 secret, SHA-1 HMAC, 30s window) + Replay Nonce Guard + 8 Single-Use HMAC-hashed Recovery Codes | Credential stuffing, phishing, and TOTP token replay within the 30-second window | `src/Crypto/TotpAuthenticator.php` |
| **Anti-AI & Bot Defense** | Stateless HMAC-signed `SHA-256 Proof-of-Work (PoW)` challenge + Single-Use Nonce Ledger + Semantic Honeytrap fields | Autonomous LLM agents, headless browser swarms, and distributed brute-force attacks | `src/Defense/BotDefenseGuard.php` |
| **Continuous Policy Engine** | Per-request risk scoring (`0–100`) evaluating Device Fingerprint, User-Agent, and `/24` IPv4 (`/48` IPv6) subnet drift + automatic 5-minute token rotation | Session cookie hijacking, XSS/infostealer token theft, and Adversary-in-the-Middle (AiTM) replay | `src/Policy/ZeroTrustPolicyEngine.php` |
| **Application-Layer WAF** | Deep request inspection + per-request 128-bit cryptographic `Content-Security-Policy` (CSP) nonce + HSTS Preload + `COOP`/`CORP` | SQL Injection (SQLi), Reflected/Stored XSS, Path Traversal, Deserialization, Command Injection | `src/Defense/WafMiddleware.php` |
| **Tamper-Evident Audit Ledger** | Blockchain-style `HMAC-SHA256` hash-chained log entries (`prev_hash -> entry_hash`) with AEAD-encrypted JSON context | Insider database modification, log deletion, or forensic evidence tampering | `src/Audit/AuditLedger.php` |

## Zero-Trust Continuous Evaluation Lifecycle

1. **Pre-Authentication Perimeter (`WafMiddleware` + `RateLimiter`)**:
   Every incoming HTTP request first receives a unique 128-bit CSP nonce and strict isolation headers (`X-Frame-Options: DENY`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy: same-origin`). Request URI, query parameters, POST body, and headers are inspected against exploit signatures before touching business logic.
2. **Anti-Automation Proof-of-Work (`BotDefenseGuard`)**:
   Before any login or identity registration request is processed, the client must solve a signed cryptographic SHA-256 Proof-of-Work puzzle (`hash("sha256", nonce . ":" . solution)` starting with `N` leading hex zeroes). Even if an automated AI agent or botnet coordinates thousands of headless browsers, each attempt requires verifiable CPU work and consumes a single-use challenge nonce stored in `used_nonces`.
3. **Multi-Factor Identity Verification (`ZeroTrustAuthService`)**:
   Passwords are first peppered with a 256-bit secret (`ZT_AUTH_PEPPER_SECRET`) via `HMAC-SHA256` and verified against an `Argon2id` hash. Missing accounts trigger a constant-time dummy Argon2id verification so response timing never reveals whether an account exists. Next, the user's encrypted `RFC 6238 TOTP` secret (or a single-use backup recovery code) is decrypted in memory, verified, and immediately zeroized via `sodium_memzero()`.
4. **Continuous Session Risk Scoring (`ZeroTrustPolicyEngine`)**:
   Upon authentication, a 256-bit random token is issued inside a `__Host-zt_token` (`Secure; HttpOnly; SameSite=Strict`) cookie, while only its blind-indexed hash is stored in `zt_sessions` alongside hashes of the client's device fingerprint and network subnet. On **every subsequent request**, the policy engine computes a live risk score (`0–100`):
   - **Score `0–39` (`ALLOW`)**: Request proceeds; session token transparently rotates every 5 minutes (`ZT_SESSION_ROTATION_INTERVAL=300`).
   - **Score `40–74` (`STEP_UP_MFA`)**: Triggered by moderate network drift; challenges the user for step-up re-authentication.
   - **Score `75–100` (`DENY_TERMINATE`)**: Triggered when both device fingerprint and IP subnet mismatch (indicating a stolen session cookie); immediately revokes the session in the database and logs a `CRITICAL` event.
5. **Cryptographic Hash-Chained Audit Trail (`AuditLedger`)**:
   Every security event is encrypted via AEAD (`XChaCha20-Poly1305` / `AES-256-GCM`) with `event_id|event_type|severity` bound as Associated Authenticated Data (`AAD`) and linked to the preceding log entry's `entry_hash`.

## Repository Directory Structure

```text
zero-trust-php-app/
├── bin/
│   └── verify-ledger.php              # CLI Cryptographic Key Generator & Audit Chain Verifier
├── docker/
│   └── nginx.conf                     # Hardened Nginx reverse-proxy & FastCGI configuration
├── public/
│   ├── .htaccess                      # Apache gateway hardening rules
│   └── index.php                      # Zero-Trust Security Portal, WAF Gateway & WebCrypto PoW UI
├── src/
│   ├── Audit/
│   │   └── AuditLedger.php            # Tamper-evident SHA-256 hash-chained & AEAD-encrypted audit log
│   ├── Auth/
│   │   └── ZeroTrustAuthService.php   # Registration, Argon2id+Pepper login, TOTP MFA & CSRF tokens
│   ├── Core/
│   │   ├── Config.php                 # Strict environment & 256-bit key configuration loader
│   │   └── Database.php               # Hardened PDO manager (SQLite WAL / MySQL) & schema migrations
│   ├── Crypto/
│   │   ├── CryptoEngine.php           # XChaCha20-Poly1305 / AES-256-GCM AEAD, HKDF-SHA256 & Argon2id
│   │   └── TotpAuthenticator.php      # RFC 6238 TOTP generator/verifier & single-use recovery codes
│   ├── Defense/
│   │   ├── BotDefenseGuard.php        # Stateless SHA-256 Proof-of-Work challenge & replay protection
│   │   ├── RateLimiter.php            # Sliding-window & exponential backoff brute-force limiter
│   │   └── WafMiddleware.php          # Application-layer WAF & nonce-based CSP header enforcer
│   ├── Policy/
│   │   └── ZeroTrustPolicyEngine.php  # Continuous adaptive risk scoring & session hijack termination
│   └── Bootstrap.php                  # Self-contained PSR-4 autoloader & PHP runtime hardening
├── storage/
│   ├── cache/                         # Isolated runtime cache directory
│   ├── database/                      # Encrypted SQLite WAL database storage
│   └── logs/                          # Application error logs
├── tests/
│   └── SecurityTest.php               # Automated adversarial & cryptographic verification suite
├── .env.example                       # Reference security environment configuration
├── .gitignore                         # Strict secret and runtime exclusion rules
├── composer.json                      # Composer package manifest & convenience scripts
├── docker-compose.yml                 # Read-only container orchestration with dropped capabilities
├── Dockerfile                         # Hardened PHP 8.3 FPM Alpine container image
├── README.md                          # Architecture & operational documentation
└── SECURITY.md                        # Threat model, cryptographic specifications & disclosure policy
```

## Quick Start & Installation

### 1. Prerequisites

- **PHP 8.2 or newer** (`php-pdo`, `php-sodium`, `php-openssl`, `php-mbstring`)
- **SQLite 3** (enabled by default for zero-configuration deployment) or **MySQL 8.0+ / PostgreSQL 15+**
- **Composer** (optional — `src/Bootstrap.php` includes a built-in strict PSR-4 autoloader so the repository runs out-of-the-box even without Composer)

### 2. Local Setup & Cryptographic Key Provisioning

```bash
# 1. Copy the environment configuration template
cp .env.example .env

# 2. Generate fresh 256-bit CSPRNG master keys for your .env file
php bin/verify-ledger.php --generate-keys

# 3. Run the automated security & adversarial test suite
php tests/SecurityTest.php

# 4. Launch the local Zero-Trust Gateway on http://127.0.0.1:8080
php -S 127.0.0.1:8080 -t public
```

### 3. Hardened Docker Deployment

The included `Dockerfile` and `docker-compose.yml` run PHP-FPM inside a read-only root filesystem (`read_only: true`), drop all Linux kernel capabilities (`cap_drop: ALL`), enforce `no-new-privileges:true`, and disable dangerous PHP execution functions (`exec`, `shell_exec`, `system`, `proc_open`, `popen`).

```bash
docker compose up -d --build
```

Once running, access the Zero-Trust Gateway at `http://localhost:8443`.

## Verifying the Tamper-Evident Audit Ledger

You can verify the cryptographic hash chain and AEAD authentication tags of every historical audit record at any time via the CLI or the JSON verification endpoint:

```bash
# Run CLI verification across all blocks from Genesis (0000...0000)
php bin/verify-ledger.php
```

Example output when all blocks and AEAD payloads are intact:

```text
[*] Verifying Zero-Trust Hash-Chained Audit Ledger & AEAD Tags...
[OK] Ledger Integrity Verified: 14 cryptographic blocks authenticated.
```

If an attacker with direct database access alters a single byte or deletes a row in `audit_ledger`, `bin/verify-ledger.php` exits with code `1` and pinpoints the exact compromised block ID.

## Security Hardening Checklist for Production

1. **Hardware Security Module (HSM) / KMS Integration**: Inject `ZT_MASTER_ENCRYPTION_KEY`, `ZT_AUTH_PEPPER_SECRET`, and `ZT_TOKEN_SIGNING_KEY` directly from AWS KMS, HashiCorp Vault, or Docker Secrets into container environment variables rather than storing them on disk.
2. **TLS 1.3 Termination**: Terminate TLS 1.3 at your edge load balancer or Nginx gateway so the `__Host-zt_token` cookie prefix is enforced by all modern browsers.
3. **Tune Proof-of-Work Difficulty**: Adjust `ZT_POW_DIFFICULTY` in `.env` (default `4` = ~65,536 SHA-256 iterations, ~150ms in browser WebCrypto; increase to `5` under active DDoS or credential-stuffing campaigns).
4. **External Log Anchoring**: Periodically ship the latest `entry_hash` from `audit_ledger` to an immutable remote sink (such as an append-only S3 Object Lock bucket) to prevent full-database truncation attacks.

## License

Released under the MIT License. See `SECURITY.md` for cryptographic specifications and vulnerability reporting guidelines.
