## Summary of Changes

<!-- Briefly describe what this Pull Request changes and why. -->

## Related Issue

<!-- Link any related issue, e.g., Closes #12 -->

## Security & Quality Verification Checklist

- [ ] `composer validate --strict` passes with no errors
- [ ] `php tests/SecurityTest.php` passes all adversarial security assertions
- [ ] `./vendor/bin/phpunit --colors=always` passes all unit and integration tests
- [ ] `./vendor/bin/phpstan analyse --memory-limit=512M` passes at Level 6 with `0 errors`
- [ ] `php bin/verify-ledger.php` confirms cryptographic audit chain integrity
- [ ] All secret/MAC comparisons use constant-time `hash_equals()` and sensitive buffers are wiped via `CryptoEngine::wipe()`
- [ ] UI changes (if any) comply with [`ACCESSIBILITY.md`](ACCESSIBILITY.md) (WCAG 2.1 Level AA)
- [ ] No `.env` files, keys, or `.sqlite` databases are included in this PR
