<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PDO;
use PHPUnit\Framework\TestCase;
use ZeroTrust\Auth\ZeroTrustAuthService;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\TotpAuthenticator;
use ZeroTrust\Policy\ZeroTrustPolicyEngine;
use ZeroTrust\Storage\SqliteStorage;
use ZeroTrust\Storage\StorageFactory;

final class AuthFlowTest extends TestCase
{
    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        Database::setConnection($pdo);
        StorageFactory::setInstance(new SqliteStorage());
    }

    public function testFullRegistrationLoginAndHijackDetection(): void
    {
        $clientIp = '203.0.113.45';
        $server = [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Linux"',
        ];

        $reg = ZeroTrustAuthService::registerUser([
            'username' => 'alice_secops',
            'email' => 'alice@zerotrust.test',
            'password' => 'Ultra$ecureZeroTrust2026!',
            'client_fingerprint' => hash('sha256', 'test-fp-alice'),
        ], $clientIp, false);

        $this->assertTrue($reg['success']);
        $this->assertArrayHasKey('totp_secret', $reg);

        $totp = TotpAuthenticator::getCode((string) ($reg['totp_secret'] ?? ''));

        $auth = ZeroTrustAuthService::authenticate([
            'username' => 'alice_secops',
            'password' => 'Ultra$ecureZeroTrust2026!',
            'totp_code' => $totp,
            'client_fingerprint' => hash('sha256', 'test-fp-alice'),
        ], $clientIp, $server, false);

        $this->assertTrue($auth['success']);
        $this->assertArrayHasKey('session_token', $auth);
        $sessionToken = (string) ($auth['session_token'] ?? '');

        $eval = ZeroTrustAuthService::verifyAndEvaluateSession(
            $sessionToken,
            $clientIp,
            $server
        );
        $this->assertTrue($eval['authenticated']);
        $this->assertSame(ZeroTrustPolicyEngine::DECISION_ALLOW, $eval['decision']);

        $hijackServer = [
            'HTTP_USER_AGENT' => 'python-requests/2.31.0',
            'HTTP_ACCEPT_LANGUAGE' => 'ru-RU',
            'HTTP_SEC_CH_UA_PLATFORM' => '"Windows"',
        ];
        $hijack = ZeroTrustAuthService::verifyAndEvaluateSession(
            $sessionToken,
            '198.51.100.99',
            $hijackServer
        );
        $this->assertFalse($hijack['authenticated']);
        $this->assertSame(ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE, $hijack['decision']);
    }
}
