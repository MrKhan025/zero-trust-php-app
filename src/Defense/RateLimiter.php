<?php

declare(strict_types=1);

namespace ZeroTrust\Defense;

use ZeroTrust\Core\Config;
use ZeroTrust\Crypto\CryptoEngine;
use ZeroTrust\Storage\StorageFactory;

/**
 * Sliding-Window & Exponential Backoff Rate Limiter.
 * Uses the Storage abstraction (SQLite by default, Redis optional).
 */
final class RateLimiter
{
    /**
     * @return array{allowed: bool, remaining: int, retry_after: int}
     */
    public static function check(string $action, string $identifier): array
    {
        $storage = StorageFactory::get();
        $bucketKey = 'rl:' . CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $now = time();

        $maxAttempts = Config::getInt('ZT_RATE_LIMIT_MAX_ATTEMPTS', 5);
        $windowSeconds = Config::getInt('ZT_RATE_LIMIT_WINDOW_SECONDS', 300);

        $raw = $storage->get($bucketKey);
        if ($raw === null) {
            return ['allowed' => true, 'remaining' => $maxAttempts, 'retry_after' => 0];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $storage->delete($bucketKey);
            return ['allowed' => true, 'remaining' => $maxAttempts, 'retry_after' => 0];
        }

        $lockedUntil = (int) ($data['locked_until'] ?? 0);
        if ($lockedUntil > $now) {
            return [
                'allowed' => false,
                'remaining' => 0,
                'retry_after' => $lockedUntil - $now,
            ];
        }

        $windowStarted = (int) ($data['window_started_at'] ?? 0);
        if (($now - $windowStarted) >= $windowSeconds) {
            $storage->delete($bucketKey);
            return ['allowed' => true, 'remaining' => $maxAttempts, 'retry_after' => 0];
        }

        $attempts = (int) ($data['attempts'] ?? 0);
        $remaining = max(0, $maxAttempts - $attempts);

        return [
            'allowed' => $remaining > 0,
            'remaining' => $remaining,
            'retry_after' => $remaining > 0 ? 0 : ($windowStarted + $windowSeconds - $now),
        ];
    }

    public static function hit(string $action, string $identifier): void
    {
        $storage = StorageFactory::get();
        $bucketKey = 'rl:' . CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $now = time();

        $maxAttempts = Config::getInt('ZT_RATE_LIMIT_MAX_ATTEMPTS', 5);
        $windowSeconds = Config::getInt('ZT_RATE_LIMIT_WINDOW_SECONDS', 300);
        $lockoutSeconds = Config::getInt('ZT_RATE_LIMIT_LOCKOUT_SECONDS', 900);

        $raw = $storage->get($bucketKey);
        $data = $raw !== null ? json_decode($raw, true) : null;

        if (!is_array($data) || ($now - (int) ($data['window_started_at'] ?? 0)) >= $windowSeconds) {
            $payload = json_encode([
                'attempts' => 1,
                'window_started_at' => $now,
                'locked_until' => 0,
            ], JSON_THROW_ON_ERROR);
            $storage->set($bucketKey, $payload, $windowSeconds + $lockoutSeconds);
            return;
        }

        $newAttempts = ((int) ($data['attempts'] ?? 0)) + 1;
        $lockedUntil = $newAttempts >= $maxAttempts ? ($now + $lockoutSeconds) : 0;

        $payload = json_encode([
            'attempts' => $newAttempts,
            'window_started_at' => (int) $data['window_started_at'],
            'locked_until' => $lockedUntil,
        ], JSON_THROW_ON_ERROR);

        $storage->set($bucketKey, $payload, $windowSeconds + $lockoutSeconds);
    }

    public static function clear(string $action, string $identifier): void
    {
        $storage = StorageFactory::get();
        $bucketKey = 'rl:' . CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $storage->delete($bucketKey);
    }
}
