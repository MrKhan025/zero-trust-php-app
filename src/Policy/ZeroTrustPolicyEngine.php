<?php

declare(strict_types=1);

namespace ZeroTrust\Policy;

use ZeroTrust\Core\Config;
use ZeroTrust\Crypto\CryptoEngine;
use ZeroTrust\Defense\BotDefenseGuard;

/**
 * Continuous Adaptive Risk & Trust Evaluation Engine (zerotrust-php).
 *
 * Evaluates every incoming request against cryptographic session context,
 * network telemetry, device fingerprint binding, and behavioral anomalies.
 * Never trusts an existing session cookie implicitly.
 */
final class ZeroTrustPolicyEngine
{
    public const DECISION_ALLOW = 'ALLOW';
    public const DECISION_STEP_UP_MFA = 'STEP_UP_MFA';
    public const DECISION_DENY_TERMINATE = 'DENY_TERMINATE';

    /**
     * Computes a deterministic, privacy-preserving device fingerprint hash from
     * normalized HTTP client characteristics and TLS/client hints.
     *
     * @param array<string, mixed> $server
     */
    public static function computeDeviceFingerprint(array $server, ?string $clientFingerprint = null): string
    {
        $components = [
            (string) ($server['HTTP_USER_AGENT'] ?? 'unknown-ua'),
            (string) ($server['HTTP_ACCEPT_LANGUAGE'] ?? 'unknown-lang'),
            (string) ($server['HTTP_SEC_CH_UA'] ?? 'no-ch-ua'),
            (string) ($server['HTTP_SEC_CH_UA_PLATFORM'] ?? 'no-ch-platform'),
            (string) ($server['HTTP_SEC_CH_UA_MOBILE'] ?? 'no-ch-mobile'),
        ];

        if ($clientFingerprint !== null && $clientFingerprint !== '') {
            $components[] = $clientFingerprint;
        }

        return CryptoEngine::blindIndex(implode('||', $components), 'device-fingerprint');
    }

    /**
     * Computes a blind index of the client's IP subnet (/24 for IPv4, /48 for IPv6).
     */
    public static function computeIpSubnetHash(string $clientIp): string
    {
        $subnet = BotDefenseGuard::extractIpSubnet($clientIp);
        return CryptoEngine::blindIndex($subnet, 'ip-subnet');
    }

    /**
     * Computes a blind index of the exact User-Agent string.
     */
    public static function computeUserAgentHash(string $userAgent): string
    {
        return CryptoEngine::blindIndex($userAgent, 'user-agent');
    }

    /**
     * Evaluates an active session against live request telemetry and returns a composite
     * risk score (0-100), list of triggered risk signals, and an enforcement decision.
     *
     * @param array<string, mixed> $sessionRow
     * @param array<string, mixed> $server
     * @return array{risk_score: int, decision: string, signals: list<string>, rotate_token: bool}
     */
    public static function evaluateSession(
        array $sessionRow,
        string $clientIp,
        array $server,
        bool $requiresHighAssurance = false
    ): array {
        $now = time();
        $riskScore = 0;
        $signals = [];

        // 1. Check explicit revocation or absolute expiration
        if ((int) ($sessionRow['revoked'] ?? 0) === 1) {
            return [
                'risk_score' => 100,
                'decision' => self::DECISION_DENY_TERMINATE,
                'signals' => ['SESSION_EXPLICITLY_REVOKED'],
                'rotate_token' => false,
            ];
        }

        $expiresAt = (int) ($sessionRow['expires_at'] ?? 0);
        if ($now >= $expiresAt) {
            return [
                'risk_score' => 100,
                'decision' => self::DECISION_DENY_TERMINATE,
                'signals' => ['SESSION_ABSOLUTE_TTL_EXPIRED'],
                'rotate_token' => false,
            ];
        }

        // 2. Check Idle Timeout
        $lastActiveAt = (int) ($sessionRow['last_active_at'] ?? 0);
        $idleTimeout = Config::getInt('ZT_SESSION_IDLE_TIMEOUT', 900);
        if (($now - $lastActiveAt) > $idleTimeout) {
            return [
                'risk_score' => 95,
                'decision' => self::DECISION_DENY_TERMINATE,
                'signals' => ['SESSION_IDLE_TIMEOUT_EXCEEDED'],
                'rotate_token' => false,
            ];
        }

        // 3. Verify Device Fingerprint Binding (Detect Session Hijacking / Cookie Theft)
        $currentDeviceFp = self::computeDeviceFingerprint($server);
        $storedDeviceFp = (string) ($sessionRow['device_fingerprint_hash'] ?? '');
        if (!hash_equals($storedDeviceFp, $currentDeviceFp)) {
            $riskScore += 55;
            $signals[] = 'DEVICE_FINGERPRINT_MISMATCH';
        }

        // 4. Verify User-Agent Binding
        $currentUaHash = self::computeUserAgentHash((string) ($server['HTTP_USER_AGENT'] ?? ''));
        $storedUaHash = (string) ($sessionRow['user_agent_hash'] ?? '');
        if (!hash_equals($storedUaHash, $currentUaHash)) {
            $riskScore += 35;
            $signals[] = 'USER_AGENT_DRIFT_DETECTED';
        }

        // 5. Verify Network IP Subnet Binding (Detect ASN / Geo / Network Roaming)
        $currentSubnetHash = self::computeIpSubnetHash($clientIp);
        $storedSubnetHash = (string) ($sessionRow['ip_subnet_hash'] ?? '');
        if (!hash_equals($storedSubnetHash, $currentSubnetHash)) {
            $riskScore += 45;
            $signals[] = 'IP_SUBNET_DRIFT_DETECTED';
        }

        // 6. Check MFA Assurance Level for Sensitive Operations
        $mfaVerified = (int) ($sessionRow['mfa_verified'] ?? 0) === 1;
        if ($requiresHighAssurance && !$mfaVerified) {
            $riskScore += 50;
            $signals[] = 'HIGH_ASSURANCE_MFA_REQUIRED';
        }

        // 7. Inspect suspicious automated/headless User-Agent signatures
        $rawUa = strtolower((string) ($server['HTTP_USER_AGENT'] ?? ''));
        if ($rawUa === '' || preg_match('/(curl|wget|python-requests|headlesschrome|phantomjs|puppeteer|playwright|sqlmap|nikto)/i', $rawUa) === 1) {
            $riskScore += 40;
            $signals[] = 'AUTOMATED_AGENT_SIGNATURE';
        }

        $riskScore = min(100, $riskScore);

        // Determine Policy Decision
        $stepUpThreshold = Config::getInt('ZT_RISK_STEP_UP_THRESHOLD', 40);
        $terminateThreshold = Config::getInt('ZT_RISK_TERMINATE_THRESHOLD', 75);

        if ($riskScore >= $terminateThreshold) {
            $decision = self::DECISION_DENY_TERMINATE;
        } elseif ($riskScore >= $stepUpThreshold) {
            $decision = self::DECISION_STEP_UP_MFA;
        } else {
            $decision = self::DECISION_ALLOW;
        }

        // Determine whether session token rotation is due
        $lastRotatedAt = (int) ($sessionRow['last_rotated_at'] ?? 0);
        $rotationInterval = Config::getInt('ZT_SESSION_ROTATION_INTERVAL', 300);
        $rotateToken = ($now - $lastRotatedAt) >= $rotationInterval;

        return [
            'risk_score' => $riskScore,
            'decision' => $decision,
            'signals' => $signals,
            'rotate_token' => $rotateToken,
        ];
    }
}
