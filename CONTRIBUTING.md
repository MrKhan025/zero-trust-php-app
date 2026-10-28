# Contributing to `zerotrust-php`

Thank you for your interest in contributing to **`zerotrust-php`**. Every contribution—whether cryptographic hardening, adversarial test coverage, accessibility improvements, or documentation—helps strengthen open-source Zero-Trust engineering in PHP.

By participating in this project, you agree to abide by our [Code of Conduct](https://www.google.com/search?q=CODE_OF_CONDUCT.md).

## 1. Reporting Security Vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.**

Please follow the responsible disclosure process in [SECURITY.md](SECURITY.md):
1. Provide a minimal Proof-of-Concept (PoC) and the affected component path privately to the maintainers.
2. Include diagnostic output from `php tests/SecurityTest.php` and `php bin/verify-ledger.php` when relevant.

## 2. Development Environment Setup

### Prerequisites
- **PHP 8.2 – 8.6** (CI runs on **PHP 8.4, 8.5, and 8.6** across **Ubuntu 26.04, Ubuntu 24.04, macOS 15, and Windows Server 2025**)
- Required extensions: `pdo`, `pdo_sqlite`, `sodium`, `openssl`, `mbstring`, `json`, `hash`
- Optional extension: `redis` (for `RedisStorage` integration and static analysis)
- **Composer 2.x**

### Local Bootstrap
```bash
# 1. Clone your fork
git clone https://github.com/MrKhan025/zerotrust-php.git
cd zerotrust-php

# 2. Install development dependencies (PHPUnit 11 & PHPStan 2.2)
composer install

# 3. Initialize environment config & generate 256-bit keys
cp .env.example .env
php bin/verify-ledger.php --generate-keys

# 4. Start the local development server
composer serve
```

## 3. Mandatory Quality Gates

Every Pull Request is automatically validated by `.github/workflows/ci.yml`. Before opening a PR, run all four verification checks locally:

```bash
# 1. Validate composer.json schema
composer validate --strict

# 2. Run the adversarial security verification suite
php tests/SecurityTest.php

# 3. Run the PHPUnit 11 test suite
./vendor/bin/phpunit --colors=always

# 4. Run PHPStan 2.2 static analysis at Level 6
./vendor/bin/phpstan analyse --memory-limit=512M

# 5. Verify cryptographic audit ledger integrity
php bin/verify-ledger.php
```

## 4. Coding, Cryptographic & Accessibility Standards

### PHP & Static Analysis Standards
- Declare `declare(strict_types=1);` at the top of every PHP file.
- Provide explicit native parameter and return types on all methods, plus PHPDoc iterable value types (`@param array<string, mixed>`, `@return list<string>`) to satisfy **PHPStan Level 6**.
- Keep classes `final` by default unless extension is explicitly required by an interface (`StorageInterface`).

### Cryptographic & Database Invariants
- **Constant-Time Comparisons**: Always use `hash_equals()` when comparing MACs, signatures, TOTP codes, recovery hashes, or blind indexes.
- **Context Separation**: Never use `ZT_MASTER_ENCRYPTION_KEY` directly; derive a purpose-specific subkey via `CryptoEngine::deriveSubkey($context)`.
- **AEAD Binding**: Always bind a canonical Associated Authenticated Data (`AAD`) string (such as `uuid|field` or `event_id|event_type|severity`) when calling `CryptoEngine::encrypt()` and `CryptoEngine::decrypt()`.
- **Memory Hygiene**: Zeroize temporary secret buffers in `finally` blocks using `CryptoEngine::wipe($secret)`.
- **Strict Prepared Statements**: Never interpolate variables into SQL queries. Keep `PDO::ATTR_EMULATE_PREPARES => false` enabled at all times.

### Accessibility Standards (WCAG 2.1 AA)
- Review [ACCESSIBILITY.md](https://www.google.com/search?q=ACCESSIBILITY.md) before modifying `public/index.php`.
- Ensure all form inputs have explicit `<label for="...">` elements and standard `autocomplete` tokens.
- Keep anti-bot honeytrap elements isolated from assistive technologies using `aria-hidden="true"` and `tabindex="-1"`.

## 5. Pull Request Checklist

- [ ] Branch created from the latest `main` branch (`git checkout -b feat/your-feature`).
- [ ] `php tests/SecurityTest.php` passes (`14 Passed, 0 Failed`).
- [ ] `./vendor/bin/phpunit` passes all unit and integration tests.
- [ ] `./vendor/bin/phpstan analyse --memory-limit=512M` reports `0 errors`.
- [ ] Documentation (`README.md`, `SECURITY.md`, or `ACCESSIBILITY.md`) updated if behavior, configuration, or UI changed.
- [ ] No `.env` files, production keys, or `.sqlite` database files are committed.
