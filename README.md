# Zero-Trust PHP App – Upgrade Package

This archive contains all the new and replacement files discussed for upgrading
https://github.com/MrKhan025/zero-trust-php-app

## Contents

- LICENSE, CONTRIBUTING.md, CI workflow, phpstan.neon, phpunit.xml
- Full Storage abstraction (SQLite + optional Redis)
- Updated RateLimiter
- Complete pure-PHP WebAuthnService (with CBOR + ES256 COSE support)
- Expanded PHPUnit test suite
- Application checklist and migration notes

## How to apply

1. Read `docs/APPLY_CHECKLIST.md`
2. Copy the files into your repository following the checklist order
3. Apply the manual patches described in the conversation for:
   - `src/Core/Database.php`
   - `src/Defense/BotDefenseGuard.php`
   - `src/Policy/ZeroTrustPolicyEngine.php`
   - `src/Auth/ZeroTrustAuthService.php`
   - `public/index.php`
   - `.env.example`
   - `composer.json`

4. Run:
   ```bash
   composer install
   cp .env.example .env
   php bin/verify-ledger.php --generate-keys
   ./vendor/bin/phpunit
   php tests/SecurityTest.php
   ```

## Notes

- Redis is optional. Default remains SQLite.
- WebAuthn is pure PHP (no external library required).
- All new code follows the existing strict_types + static method style.
