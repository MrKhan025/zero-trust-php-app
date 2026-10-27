# Contributing to ZeroTrust Shield (`zero-trust-php-app`)

Thank you for your interest in improving this Zero-Trust reference implementation.

## Security Issues

**Do not open public GitHub issues for vulnerabilities.**

Follow the process in [SECURITY.md](SECURITY.md):
1. Provide a minimal PoC and affected component path privately.
2. Include output of `php tests/SecurityTest.php` and `php bin/verify-ledger.php` when relevant.

## Development Setup

```bash
cp .env.example .env
php bin/verify-ledger.php --generate-keys
composer install
php tests/SecurityTest.php
./vendor/bin/phpunit
php -S 127.0.0.1:8080 -t public
```

## What We Welcome

- Bug fixes and security hardening
- Additional adversarial test cases
- WebAuthn / Passkeys support
- Redis-backed rate limiting / nonce store
- Improved device fingerprinting
- Better observability (metrics, structured logs)
- Documentation improvements
- Docker / deployment refinements

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Keep changes focused. Prefer small, reviewable PRs.
3. Run the security test suite locally:
   ```bash
   php tests/SecurityTest.php
   ./vendor/bin/phpunit
   ```
4. If you added PHP code, ensure it passes static analysis:
   ```bash
   vendor/bin/phpstan analyse
   ```
5. Update documentation (README / SECURITY.md) if behavior or threat model changes.
6. Do not commit `.env`, real keys, or database files.

## Coding Standards

- PHP 8.2+ with `declare(strict_types=1);`
- Prefer pure functions / static methods in the current architecture unless a clear reason for DI exists
- Constant-time comparisons (`hash_equals`) for any secret/MAC comparison
- Zeroize sensitive material with `CryptoEngine::wipe()` / `sodium_memzero` where practical
- No emulated PDO prepares
- Keep cryptographic parameters explicit and documented

Thank you for helping make Zero-Trust authentication stronger and more accessible in PHP.
