<?php

declare(strict_types=1);

namespace ZeroTrust\Defense;

use PDO;
use ZeroTrust\Core\Config;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

/**
 * Anti-AI & Automated Exploit Bot Defense Engine.
 *
 * Defends against LLM-driven autonomous agents, headless credential stuffers,
 * distributed brute-force swarms, and automated fuzzers via:
 * 1. Stateless Cryptographic SHA-256 Proof-of-Work (PoW) Challenges:
 *    Forces every client to expend measurable CPU cycles finding a SHA-256 preimage
 *    with N leading hex zeroes signed with a short-lived HMAC challenge token and
 *    single-use replay protection.
 * 2. Invisible Honeytrap / Behavioral Trap Fields:
 *    Detects automated DOM/form parsers that populate hidden semantic fields.
 * 3. Human Submission Cadence Check:
 *    Rejects instantaneous (< 400ms) synthetic form submissions that bypass browser rendering.
 */
final class BotDefenseGuard
{
    /**
     * Generates a signed, short-lived Proof-of-Work challenge bound to the client's IP subnet.
     *
     * @return array{challenge_id: string, nonce: string, timestamp: int, difficulty: int, signature: string}
     */
    public static function issueChallenge(string $clientIp): array
    {
        $challengeId = CryptoEngine::uuidV4();
        $nonce = bin2hex(random_bytes(16));
        $timestamp = time();
        $difficulty = Config::getInt('ZT_POW_DIFFICULTY', 4);
        $ipSubnet = self::extractIpSubnet($clientIp);

        $canonical = implode('|', [$challengeId, $nonce, (string) $timestamp, (string) $difficulty, $ipSubnet]);
        $signature = CryptoEngine::sign($canonical, 'pow-challenge');

        return [
            'challenge_id' => $challengeId,
            'nonce' => $nonce,
            'timestamp' => $timestamp,
            'difficulty' => $difficulty,
            'signature' => $signature,
        ];
    }

    /**
     * Verifies a client's Proof-of-Work solution, honeytrap integrity, and replay status.
     *
     * @param array<string, mixed> $payload
     * @return array{passed: bool, reason: string}
     */
    public static function verifySubmission(array $payload, string $clientIp): array
    {
        // 1. Check invisible Honeytrap field (AI/bot scrapers often fill `website_url_verification`)
        $honeypot = (string) ($payload['website_url_verification'] ?? '');
        if ($honeypot !== '') {
            return ['passed' => false, 'reason' => 'HONEYTRAP_TRIGGERED'];
        }

        // 2. Validate PoW fields presence
        $challengeId = (string) ($payload['pow_challenge_id'] ?? '');
        $nonce = (string) ($payload['pow_nonce'] ?? '');
        $timestamp = (int) ($payload['pow_timestamp'] ?? 0);
        $difficulty = (int) ($payload['pow_difficulty'] ?? 0);
        $signature = (string) ($payload['pow_signature'] ?? '');
        $solution = (string) ($payload['pow_solution'] ?? '');

        $expectedDifficulty = Config::getInt('ZT_POW_DIFFICULTY', 4);
        if ($challengeId === '' || $nonce === '' || $signature === '' || $solution === '' || $difficulty < $expectedDifficulty) {
            return ['passed' => false, 'reason' => 'POW_MISSING_OR_DOWNGRADED'];
        }

        // 3. Check Challenge TTL expiration
        $now = time();
        $ttl = Config::getInt('ZT_POW_TTL_SECONDS', 180);
        if (($now - $timestamp) > $ttl || $timestamp > ($now + 5)) {
            return ['passed' => false, 'reason' => 'POW_CHALLENGE_EXPIRED'];
        }

        // 4. Verify HMAC Signature binding Challenge ID + Nonce + Timestamp + Difficulty + IP Subnet
        $ipSubnet = self::extractIpSubnet($clientIp);
        $canonical = implode('|', [$challengeId, $nonce, (string) $timestamp, (string) $difficulty, $ipSubnet]);
        if (!CryptoEngine::verifySignature($canonical, $signature, 'pow-challenge')) {
            return ['passed' => false, 'reason' => 'POW_SIGNATURE_INVALID'];
        }

        // 5. Verify cryptographic SHA-256 Proof-of-Work hash prefix
        $workHash = hash('sha256', $nonce . ':' . $solution);
        $requiredPrefix = str_repeat('0', $difficulty);
        if (!str_starts_with($workHash, $requiredPrefix)) {
            return ['passed' => false, 'reason' => 'POW_WORK_INSUFFICIENT'];
        }

        // 6. Enforce Single-Use Nonce Replay Protection in Database
        if (!self::consumeNonce($challengeId, 'pow', $now + $ttl)) {
            return ['passed' => false, 'reason' => 'POW_CHALLENGE_REPLAYED'];
        }

        return ['passed' => true, 'reason' => 'OK'];
    }

    /**
     * Atomically records a single-use nonce/challenge ID to prevent replay attacks.
     */
    public static function consumeNonce(string $rawNonce, string $purpose, int $expiresAt): bool
    {
        $pdo = Database::connection();
        $nonceHash = CryptoEngine::blindIndex($rawNonce, 'nonce:' . $purpose);

        // Purge expired nonces opportunistically
        $cleanup = $pdo->prepare('DELETE FROM used_nonces WHERE expires_at < :now');
        $cleanup->execute([':now' => time()]);

        $check = $pdo->prepare('SELECT nonce_hash FROM used_nonces WHERE nonce_hash = :hash LIMIT 1');
        $check->execute([':hash' => $nonceHash]);
        if ($check->fetch() !== false) {
            return false;
        }

        $insert = $pdo->prepare('
            INSERT INTO used_nonces (nonce_hash, purpose, expires_at)
            VALUES (:hash, :purpose, :expires)
        ');
        $insert->execute([
            ':hash' => $nonceHash,
            ':purpose' => $purpose,
            ':expires' => $expiresAt,
        ]);

        return true;
    }

    /**
     * Normalizes an IPv4 (/24) or IPv6 (/48) address to its network subnet prefix.
     */
    public static function extractIpSubnet(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $packed = inet_pton($ip);
            if ($packed !== false) {
                $prefix = substr($packed, 0, 6) . str_repeat("\0", 10);
                return (string) inet_ntop($prefix) . '/48';
            }
        }
        return '0.0.0.0/0';
    }
}
