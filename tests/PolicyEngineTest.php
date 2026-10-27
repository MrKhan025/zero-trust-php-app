<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Policy\ZeroTrustPolicyEngine;

final class PolicyEngineTest extends TestCase
{
    public function testMatchingDeviceAndIpGivesLowRisk(): void
    {
        $server = [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64)',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Linux"',
        ];

        $fp = ZeroTrustPolicyEngine::computeDeviceFingerprint($server);
        $ipHash = ZeroTrustPolicyEngine::computeIpSubnetHash('203.0.113.10');
        $uaHash = ZeroTrustPolicyEngine::computeUserAgentHash($server['HTTP_USER_AGENT']);

        $session = [
            'revoked' => 0,
            'expires_at' => time() + 3600,
            'last_active_at' => time() - 10,
            'device_fingerprint_hash' => $fp,
            'ip_subnet_hash' => $ipHash,
            'user_agent_hash' => $uaHash,
            'mfa_verified' => 1,
            'last_rotated_at' => time() - 10,
        ];

        $result = ZeroTrustPolicyEngine::evaluateSession($session, '203.0.113.10', $server);
        $this->assertSame(ZeroTrustPolicyEngine::DECISION_ALLOW, $result['decision']);
        $this->assertLessThan(40, $result['risk_score']);
    }

    public function testDeviceAndIpDriftTriggersTerminate(): void
    {
        $originalServer = [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64)',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Linux"',
        ];

        $fp = ZeroTrustPolicyEngine::computeDeviceFingerprint($originalServer);
        $ipHash = ZeroTrustPolicyEngine::computeIpSubnetHash('203.0.113.10');
        $uaHash = ZeroTrustPolicyEngine::computeUserAgentHash($originalServer['HTTP_USER_AGENT']);

        $session = [
            'revoked' => 0,
            'expires_at' => time() + 3600,
            'last_active_at' => time() - 10,
            'device_fingerprint_hash' => $fp,
            'ip_subnet_hash' => $ipHash,
            'user_agent_hash' => $uaHash,
            'mfa_verified' => 1,
            'last_rotated_at' => time() - 10,
        ];

        $hijackerServer = [
            'HTTP_USER_AGENT' => 'python-requests/2.31.0',
            'HTTP_ACCEPT_LANGUAGE' => 'ru-RU',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Windows"',
        ];

        $result = ZeroTrustPolicyEngine::evaluateSession($session, '198.51.100.50', $hijackerServer);
        $this->assertSame(ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE, $result['decision']);
        $this->assertGreaterThanOrEqual(75, $result['risk_score']);
    }
}
