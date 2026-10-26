<?php

declare(strict_types=1);

namespace ZeroTrust\Defense;

use ZeroTrust\Core\Config;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

/**
 * Sliding-Window & Exponential Backoff Rate Limiter.
 * Protects authentication, MFA, and API endpoints from brute-force and credential stuffing.
 */
final class RateLimiter
{
    /**
     * Checks whether a given action + identifier bucket is currently rate-limited.
     *
     * @return array{allowed: bool, remaining: int, retry_after: int}
     */
    public static function check(string $action, string $identifier): array
    {
        $pdo = Database::connection();
        $bucketKey = CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $now = time();

        $maxAttempts = Config::getInt('ZT_RATE_LIMIT_MAX_ATTEMPTS', 5);
        $windowSeconds = Config::getInt('ZT_RATE_LIMIT_WINDOW_SECONDS', 300);

        $stmt = $pdo->prepare('SELECT attempts, window_started_at, locked_until FROM rate_limits WHERE bucket_key = :key LIMIT 1');
        $stmt->execute([':key' => $bucketKey]);
        $row = $stmt->fetch();

        if ($row === false) {
            return ['allowed' => true, 'remaining' => $maxAttempts, 'retry_after' => 0];
        }

        $lockedUntil = (int) $row['locked_until'];
        if ($lockedUntil > $now) {
            return [
                'allowed' => false,
                'remaining' => 0,
                'retry_after' => $lockedUntil - $now,
            ];
        }

        $windowStarted = (int) $row['window_started_at'];
        if (($now - $windowStarted) >= $windowSeconds) {
            // Window expired; reset bucket
            $reset = $pdo->prepare('DELETE FROM rate_limits WHERE bucket_key = :key');
            $reset->execute([':key' => $bucketKey]);
            return ['allowed' => true, 'remaining' => $maxAttempts, 'retry_after' => 0];
        }

        $attempts = (int) $row['attempts'];
        $remaining = max(0, $maxAttempts - $attempts);

        return [
            'allowed' => $remaining > 0,
            'remaining' => $remaining,
            'retry_after' => $remaining > 0 ? 0 : ($windowStarted + $windowSeconds - $now),
        ];
    }

    /**
     * Records a failed attempt or rate-limited hit in the bucket, applying lockouts when threshold is reached.
     */
    public static function hit(string $action, string $identifier): void
    {
        $pdo = Database::connection();
        $bucketKey = CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $now = time();

        $maxAttempts = Config::getInt('ZT_RATE_LIMIT_MAX_ATTEMPTS', 5);
        $windowSeconds = Config::getInt('ZT_RATE_LIMIT_WINDOW_SECONDS', 300);
        $lockoutSeconds = Config::getInt('ZT_RATE_LIMIT_LOCKOUT_SECONDS', 900);

        $stmt = $pdo->prepare('SELECT attempts, window_started_at FROM rate_limits WHERE bucket_key = :key LIMIT 1');
        $stmt->execute([':key' => $bucketKey]);
        $row = $stmt->fetch();

        if ($row === false || ($now - (int) $row['window_started_at']) >= $windowSeconds) {
            $upsert = $pdo->prepare('
                INSERT INTO rate_limits (bucket_key, attempts, window_started_at, locked_until)
                VALUES (:key, 1, :now, 0)
                ON CONFLICT(bucket_key) DO UPDATE SET
                    attempts = 1,
                    window_started_at = :now,
                    locked_until = 0
            ');
            $upsert->execute([':key' => $bucketKey, ':now' => $now]);
            return;
        }

        $newAttempts = ((int) $row['attempts']) + 1;
        $lockedUntil = $newAttempts >= $maxAttempts ? ($now + $lockoutSeconds) : 0;

        $update = $pdo->prepare('
            UPDATE rate_limits
            SET attempts = :attempts, locked_until = :locked
            WHERE bucket_key = :key
        ');
        $update->execute([
            ':attempts' => $newAttempts,
            ':locked' => $lockedUntil,
            ':key' => $bucketKey,
        ]);
    }

    /**
     * Clears the rate-limit bucket after a verified multi-factor authentication.
     */
    public static function clear(string $action, string $identifier): void
    {
        $pdo = Database::connection();
        $bucketKey = CryptoEngine::blindIndex($action . ':' . $identifier, 'ratelimit');
        $stmt = $pdo->prepare('DELETE FROM rate_limits WHERE bucket_key = :key');
        $stmt->execute([':key' => $bucketKey]);
    }
}
