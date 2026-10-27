# ZeroTrust Shield Enterprise (`zero-trust-php-app`)

[![CI — Security Tests & Static Analysis](https://github.com/MrKhan025/zero-trust-php-app/actions/workflows/ci.yml/badge.svg)](https://github.com/MrKhan025/zero-trust-php-app/actions/workflows/ci.yml)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%20--%208.4-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Architecture](https://img.shields.io/badge/NIST-SP%20800--207%20Zero--Trust-10b981)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![Cryptography](https://img.shields.io/badge/AEAD-XChaCha20--Poly1305%20%7C%20AES--256--GCM-3b82f6)](SECURITY.md)
[![Static Analysis](https://img.shields.io/badge/PHPStan-Level%206%20(v2.2)-8b5cf6)](phpstan.neon)
[![Accessibility](https://img.shields.io/badge/WCAG-2.1%20AA%20Compliant-f59e0b)](ACCESSIBILITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)

**ZeroTrust Shield Enterprise** is a production-grade, zero-dependency PHP reference architecture implementing **NIST SP 800-207 Continuous Adaptive Authentication**, **XChaCha20-Poly1305 / AES-256-GCM Authenticated Encryption (AEAD)**, **Stateless SHA-256 Proof-of-Work (PoW) Anti-AI Bot Defense**, **RFC 6238 TOTP & Pure-PHP WebAuthn Passkeys**, and a **Tamper-Evident Cryptographic Hash-Chained Audit Ledger**.

> **Core Philosophy — Assume Breach, Verify Explicitly:** Never trust a network perimeter, an unverified form submission, or a previously issued session cookie. Every HTTP request is inspected by an application-layer WAF, bound to device and network telemetry, and logged in an AEAD-encrypted, HMAC-chained forensic ledger.

## Key Capabilities & Security Matrix

| Security Domain | Implementation Details | Core Module |
| :--- | :--- | :--- |
| **Authenticated Encryption (AEAD)** | Encrypts PII (emails, TOTP secrets, recovery codes, WebAuthn credentials, audit context) at rest using `libsodium` **XChaCha20-Poly1305-IETF** (192-bit nonce, 128-bit MAC) with automatic fallback to OpenSSL **AES-256-GCM**. Every ciphertext binds record identity via **Associated Authenticated Data (AAD)**. | [`src/Crypto/CryptoEngine.php`](src/Crypto/CryptoEngine.php) |
| **Context-Bound Key Derivation** | Derives isolated 256-bit subkeys from `ZT_MASTER_ENCRYPTION_KEY` via **HKDF-SHA256 (RFC 5869)** (`user-pii`, `user-mfa`, `audit-ledger`, `blind-index:*`) so the master key is never reused across contexts. | [`src/Crypto/CryptoEngine.php`](src/Crypto/CryptoEngine.php) |
| **Peppered Argon2id Password Hashing** | Pre-hashes passwords with **HMAC-SHA256** using an environment-isolated `ZT_AUTH_PEPPER_SECRET` before applying memory-hard **Argon2id** (`m=64 MiB, t=4, p=2`), neutralizing offline GPU/ASIC cracking even if the database is exfiltrated. | [`src/Crypto/CryptoEngine.php`](src/Crypto/CryptoEngine.php) |
| **Anti-Timing Enumeration Guard** | Executes a constant-time dummy Argon2id verification when an unknown username or email is submitted, equalizing response latency against statistical timing probes. | [`src/Auth/ZeroTrustAuthService.php`](src/Auth/ZeroTrustAuthService.php) |
| **Anti-AI Proof-of-Work (PoW) & Bot Defense** | Protects unauthenticated endpoints with a stateless HMAC-signed **SHA-256 preimage challenge**, single-use nonce replay tracking, and screen-reader-safe semantic honeytrap fields. | [`src/Defense/BotDefenseGuard.php`](src/Defense/BotDefenseGuard.php) |
| **Multi-Factor Authentication (TOTP & Passkeys)** | Full **RFC 6238 TOTP** (160-bit Base32 secrets, $\pm 1$ window drift tolerance, 30s replay prevention, 8 single-use HMAC recovery codes) plus pure-PHP **WebAuthn / Passkeys** (CBOR + COSE ES256 P-256 verification). | [`src/Crypto/TotpAuthenticator.php`](src/Crypto/TotpAuthenticator.php), [`src/Crypto/WebAuthnService.php`](src/Crypto/WebAuthnService.php) |
| **Continuous Adaptive Trust Engine** | Evaluates every request against device fingerprint, User-Agent hash, and `/24` IPv4 (`/48` IPv6) subnet binding. Automatically rotates session tokens and revokes hijacked cookies in real time. | [`src/Policy/ZeroTrustPolicyEngine.php`](src/Policy/ZeroTrustPolicyEngine.php) |
| **Application-Layer WAF & CSP Nonce** | Inspects `GET`, `POST`, `URI`, and `User-Agent` inputs for SQLi, XSS, LFI/Path Traversal, Phar/Object Deserialization, and Command Injection; emits a per-request 128-bit cryptographic `Content-Security-Policy` nonce. | [`src/Defense/WafMiddleware.php`](src/Defense/WafMiddleware.php) |
| **Hash-Chained Forensic Audit Ledger** | Chains every security event via `entry_hash = HMAC-SHA256(prev_hash \| event_id \| ...)` with AEAD-encrypted context payloads. Detects any row modification, deletion, or reordering. | [`src/Audit/AuditLedger.php`](src/Audit/AuditLedger.php) |
| **Pluggable Key-Value Storage** | Unified `StorageInterface` supporting **SQLite** out-of-the-box (zero external daemon required) and **Redis** for distributed high-throughput deployments. | [`src/Storage/`](src/Storage/) |

## Request Lifecycle & Zero-Trust Architecture

```text
Incoming HTTP Request
  │
  ├─► 1. WafMiddleware::emitSecurityHeaders() & inspectRequest()
  │      ├─ Emits HSTS, X-Frame-Options: DENY, COOP/COEP, and 128-bit CSP Nonce
  │      └─ Blocks SQLi, XSS, LFI, Deserialization, Command Injection & Null Bytes (HTTP 403)
  │
  ├─► 2. RateLimiter::check() & BotDefenseGuard::verifySubmission()
  │      ├─ Enforces sliding-window rate limits + exponential lockout via SqliteStorage / RedisStorage
  │      └─ Verifies HMAC-signed SHA-256 Proof-of-Work solution, honeytrap, and single-use nonce
  │
  ├─► 3. ZeroTrustAuthService::authenticate()
  │      ├─ Queries user via deterministic HMAC-SHA256 blind index (email remains AEAD-encrypted)
  │      ├─ Verifies HMAC-peppered Argon2id password (or runs dummy Argon2id on unknown user)
  │      └─ Verifies RFC 6238 TOTP / Recovery Code / WebAuthn Passkey with replay protection
  │
  ├─► 4. ZeroTrustPolicyEngine::evaluateSession()  [Executed on EVERY Request]
  │      ├─ Computes composite Risk Score (0–100) across Device Fingerprint, UA, and IP Subnet
  │      ├─ Risk 0–39   ──► ALLOW (auto-rotates session token every 300s)
  │      ├─ Risk 40–74  ──► STEP_UP_MFA (challenges session for additional verification)
  │      └─ Risk 75–100 ──► DENY_TERMINATE (revokes stolen/drifted session immediately)
  │
  └─► 5. AuditLedger::record()
         └─ Appends AEAD-encrypted event chained to previous block hash (Genesis -> Block N)
```

## Continuous Adaptive Risk Scoring

`ZeroTrustPolicyEngine::evaluateSession()` computes a live composite risk score (`0` to `100`) on every authenticated request:

| Telemetry Signal | Risk Weight | Trigger Condition |
| :--- | :---: | :--- |
| `SESSION_EXPLICITLY_REVOKED` | `100` | Session was logged out or terminated by policy |
| `SESSION_ABSOLUTE_TTL_EXPIRED` | `100` | Session exceeded `ZT_SESSION_ABSOLUTE_LIFETIME` (default `14400s` / 4 hours) |
| `SESSION_IDLE_TIMEOUT_EXCEEDED` | `95` | Inactivity exceeded `ZT_SESSION_IDLE_TIMEOUT` (default `900s` / 15 minutes) |
| `DEVICE_FINGERPRINT_MISMATCH` | `+55` | Normalized client hints (`User-Agent`, `Accept-Language`, `Sec-CH-UA*`) drifted |
| `HIGH_ASSURANCE_MFA_REQUIRED` | `+50` | Sensitive operation requested without hardware/TOTP MFA assurance |
| `IP_SUBNET_DRIFT_DETECTED` | `+45` | Client roamed outside bound `/24` IPv4 or `/48` IPv6 network prefix |
| `AUTOMATED_AGENT_SIGNATURE` | `+40` | Headless browser or exploit scanner signature detected (`curl`, `python-requests`, `sqlmap`, etc.) |
| `USER_AGENT_DRIFT_DETECTED` | `+35` | Exact `HTTP_USER_AGENT` string changed mid-session |

## Quick Start

### 1. Prerequisites

- **PHP 8.2, 8.3, or 8.4** with extensions: `pdo`, `pdo_sqlite`, `sodium`, `openssl`, `mbstring`, `json`, `hash` (optional: `redis`)
- **Composer** (optional—`src/Bootstrap.php` includes a built-in PSR-4 fallback autoloader so the app runs even without `vendor/`)

### 2. Local Installation & Key Generation

```bash
# Clone the repository
git clone https://github.com/MrKhan025/zero-trust-php-app.git
cd zero-trust-php-app

# Install dev dependencies (PHPUnit 11 & PHPStan 2.2)
composer install

# Copy environment configuration and generate fresh 256-bit CSPRNG keys
cp .env.example .env
php bin/verify-ledger.php --generate-keys

# Launch the built-in PHP development server
composer serve
# Or directly: php -S 127.0.0.1:8080 -t public
```

Open **`http://127.0.0.1:8080`** in your browser to access the ZeroTrust Shield interactive gateway.

### 3. Docker & Nginx Deployment

```bash
cp .env.example .env
docker compose up --build -d
```

This launches the hardened `php:8.4-fpm-alpine` container (`Dockerfile`) paired with `nginx:1.27-alpine` (`docker/nginx.conf`) on port **`8080`**.

## Running the Verification & Test Suites

```bash
# 1. Run the standalone adversarial security verification suite (14 end-to-end assertions)
php tests/SecurityTest.php

# 2. Run the PHPUnit 11 unit & integration test suite
./vendor/bin/phpunit --colors=always

# 3. Run PHPStan 2.2 static analysis (Level 6)
./vendor/bin/phpstan analyse --memory-limit=512M

# 4. Verify cryptographic hash-chained audit ledger integrity via CLI
php bin/verify-ledger.php
```

## Environment Configuration (`.env`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ZT_MASTER_ENCRYPTION_KEY` | *(64-char hex)* | 256-bit master key used by `HKDF-SHA256` to derive context-bound AEAD & blind-index subkeys |
| `ZT_AUTH_PEPPER_SECRET` | *(64-char hex)* | 256-bit secret key for `HMAC-SHA256` password peppering prior to `Argon2id` hashing |
| `ZT_TOKEN_SIGNING_KEY` | *(64-char hex)* | 256-bit secret key for signing stateless Proof-of-Work challenges, CSRF tokens, and audit blocks |
| `DB_CONNECTION` | `sqlite` | Database driver (`sqlite` default, or `mysql` / `pgsql` via `DB_DSN`) |
| `ZT_STORAGE_DRIVER` | `sqlite` | Key-value storage backend for rate limiting and WebAuthn/PoW challenges (`sqlite` or `redis`) |
| `ZT_RISK_STEP_UP_THRESHOLD` | `40` | Composite risk score threshold (`0–100`) that triggers step-up MFA verification |
| `ZT_RISK_TERMINATE_THRESHOLD` | `75` | Composite risk score threshold (`0–100`) that immediately revokes the active session |
| `ZT_POW_DIFFICULTY` | `4` | Number of leading hex zeroes required in client-side SHA-256 Proof-of-Work challenges |
| `ZT_RATE_LIMIT_MAX_ATTEMPTS` | `5` | Maximum failed attempts within `ZT_RATE_LIMIT_WINDOW_SECONDS` (`300s`) before lockout (`900s`) |

## Project Structure

```text
zero-trust-php-app/
├── .github/workflows/
│   └── ci.yml                       # GitHub Actions CI (PHP 8.4, Adversarial Suite, PHPUnit 11, PHPStan 2.2)
├── bin/
│   └── verify-ledger.php            # CLI CSPRNG key generator & cryptographic audit chain verifier
├── docker/
│   └── nginx.conf                   # Hardened Nginx reverse-proxy configuration
├── docs/
│   ├── APPLY_CHECKLIST.md           # Upgrade & architecture integration checklist
│   └── DATABASE_MIGRATION.md        # SQLite / SQL schema migration reference
├── public/
│   ├── .htaccess                    # Apache rewrite & security header rules
│   └── index.php                    # Zero-Trust Gateway UI, WAF middleware entrypoint & WebCrypto PoW solver
├── src/
│   ├── Audit/AuditLedger.php        # Tamper-evident HMAC-SHA256 hash-chained & AEAD-encrypted audit ledger
│   ├── Auth/ZeroTrustAuthService.php# Identity registration, MFA login, CSRF & continuous session evaluation
│   ├── Core/Config.php              # Immutable environment & 256-bit key configuration loader
│   ├── Core/Database.php            # Strict PDO connection manager & automatic schema migration
│   ├── Crypto/CryptoEngine.php      # XChaCha20-Poly1305 / AES-256-GCM AEAD, HKDF-SHA256, Argon2id + Pepper
│   ├── Crypto/TotpAuthenticator.php # RFC 6238 TOTP & single-use HMAC recovery codes
│   ├── Crypto/WebAuthnService.php   # Pure-PHP WebAuthn / Passkeys (CBOR + ES256 COSE verification)
│   ├── Defense/BotDefenseGuard.php  # Stateless SHA-256 Proof-of-Work, honeytrap & replay defense
│   ├── Defense/RateLimiter.php      # Sliding-window & exponential backoff rate limiter
│   ├── Defense/WafMiddleware.php    # Request payload signature inspection & CSP nonce headers
│   ├── Policy/ZeroTrustPolicyEngine.php # NIST SP 800-207 adaptive session risk scoring engine
│   ├── Storage/                     # Pluggable key-value storage abstraction (SQLite & Redis)
│   └── Bootstrap.php                # Self-contained PSR-4 autoloader & runtime security hardening
├── tests/                           # PHPUnit 11 test suite & standalone adversarial SecurityTest runner
├── ACCESSIBILITY.md                 # WCAG 2.1 AA accessibility architecture & testing standards
├── CODE_OF_CONDUCT.md               # Contributor Covenant v2.1 Code of Conduct
├── CONTRIBUTING.md                  # Developer workflow, security standards & PR guidelines
├── Dockerfile                       # Hardened PHP 8.4 FPM Alpine container image
├── docker-compose.yml               # Multi-container orchestration (PHP-FPM + Nginx)
├── LICENSE                          # MIT License
└── SECURITY.md                      # Threat model, cryptographic specifications & vulnerability disclosure
```

## Community & Governance

- **Security Policy & Threat Model**: [SECURITY.md](SECURITY.md)
- **Accessibility Statement (WCAG 2.1 AA)**: [ACCESSIBILITY.md](ACCESSIBILITY.md)
- **Contributing Guidelines**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Code of Conduct**: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **License**: [MIT License](LICENSE)
