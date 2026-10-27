# Zero-Trust PHP App – Upgrade Application Checklist

Apply the files from this package in the following order.

## 1. Hygiene & CI
- [ ] Copy `LICENSE` → repository root
- [ ] Copy `CONTRIBUTING.md` → repository root
- [ ] Copy `.github/workflows/ci.yml`
- [ ] Copy `phpstan.neon`
- [ ] Copy `phpunit.xml`
- [ ] Copy `tests/bootstrap.php`

## 2. Storage Layer
- [ ] Create directory `src/Storage/`
- [ ] Copy `src/Storage/StorageInterface.php`
- [ ] Copy `src/Storage/SqliteStorage.php`
- [ ] Copy `src/Storage/RedisStorage.php`
- [ ] Copy `src/Storage/StorageFactory.php`

## 3. Database Schema
- [ ] Update `src/Core/Database.php`:
  - Add `kv_store` table
  - Add `users.webauthn_credentials_encrypted`
  - Add `zt_sessions.client_fingerprint_hash`

## 4. Rate Limiting & Nonces
- [ ] Replace `src/Defense/RateLimiter.php` with the version in this package
- [ ] Update `BotDefenseGuard::consumeNonce()` to use `StorageFactory`

## 5. Device Fingerprinting
- [ ] Update `ZeroTrustPolicyEngine::computeDeviceFingerprint()` to accept optional `$clientFingerprint`
- [ ] Update `ZeroTrustAuthService` to extract and pass `client_fingerprint`

## 6. WebAuthn
- [ ] Copy `src/Crypto/WebAuthnService.php`

## 7. Frontend
- [ ] Add WebAuthn endpoints and client fingerprint JS to `public/index.php`

## 8. Configuration
- [ ] Update `.env.example` with:
  ```
  ZT_STORAGE_DRIVER=sqlite
  ZT_REDIS_HOST=127.0.0.1
  ZT_REDIS_PORT=6379
  ZT_REDIS_PASSWORD=
  ```
- [ ] Update `composer.json` scripts

## 9. Tests
- [ ] Copy all files from `tests/` in this package

## 10. Verify
```bash
composer install
cp .env.example .env
php bin/verify-ledger.php --generate-keys
./vendor/bin/phpunit
php tests/SecurityTest.php
```
