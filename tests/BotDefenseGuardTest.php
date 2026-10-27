<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Defense\BotDefenseGuard;
use ZeroTrust\Storage\StorageFactory;
use ZeroTrust\Storage\SqliteStorage;
use ZeroTrust\Core\Database;
use PDO;

final class BotDefenseGuardTest extends TestCase
{
    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        Database::setConnection($pdo);
        StorageFactory::setInstance(new SqliteStorage());
    }

    public function testIssueAndVerifyValidPow(): void
    {
        $ip = '203.0.113.10';
        $challenge = BotDefenseGuard::issueChallenge($ip);

        $this->assertArrayHasKey('challenge_id', $challenge);
        $this->assertArrayHasKey('nonce', $challenge);
        $this->assertArrayHasKey('signature', $challenge);

        $difficulty = (int) $challenge['difficulty'];
        $prefix = str_repeat('0', $difficulty);
        $solution = null;

        for ($i = 0; $i < 500000; $i++) {
            $cand = dechex($i);
            if (str_starts_with(hash('sha256', $challenge['nonce'] . ':' . $cand), $prefix)) {
                $solution = $cand;
                break;
            }
        }

        $this->assertNotNull($solution, 'Failed to solve PoW in time');

        $payload = [
            'pow_challenge_id' => $challenge['challenge_id'],
            'pow_nonce'        => $challenge['nonce'],
            'pow_timestamp'    => $challenge['timestamp'],
            'pow_difficulty'   => $challenge['difficulty'],
            'pow_signature'    => $challenge['signature'],
            'pow_solution'     => $solution,
            'website_url_verification' => '',
        ];

        $result = BotDefenseGuard::verifySubmission($payload, $ip);
        $this->assertTrue($result['passed']);
        $this->assertSame('OK', $result['reason']);
    }

    public function testReplayIsBlocked(): void
    {
        $ip = '203.0.113.11';
        $challenge = BotDefenseGuard::issueChallenge($ip);

        $difficulty = (int) $challenge['difficulty'];
        $prefix = str_repeat('0', $difficulty);
        $solution = null;

        for ($i = 0; $i < 500000; $i++) {
            $cand = dechex($i);
            if (str_starts_with(hash('sha256', $challenge['nonce'] . ':' . $cand), $prefix)) {
                $solution = $cand;
                break;
            }
        }

        $payload = [
            'pow_challenge_id' => $challenge['challenge_id'],
            'pow_nonce'        => $challenge['nonce'],
            'pow_timestamp'    => $challenge['timestamp'],
            'pow_difficulty'   => $challenge['difficulty'],
            'pow_signature'    => $challenge['signature'],
            'pow_solution'     => $solution,
            'website_url_verification' => '',
        ];

        $first = BotDefenseGuard::verifySubmission($payload, $ip);
        $this->assertTrue($first['passed']);

        $second = BotDefenseGuard::verifySubmission($payload, $ip);
        $this->assertFalse($second['passed']);
        $this->assertSame('POW_CHALLENGE_REPLAYED', $second['reason']);
    }

    public function testHoneytrapIsDetected(): void
    {
        $ip = '203.0.113.12';
        $challenge = BotDefenseGuard::issueChallenge($ip);

        $payload = [
            'pow_challenge_id' => $challenge['challenge_id'],
            'pow_nonce'        => $challenge['nonce'],
            'pow_timestamp'    => $challenge['timestamp'],
            'pow_difficulty'   => $challenge['difficulty'],
            'pow_signature'    => $challenge['signature'],
            'pow_solution'     => 'deadbeef',
            'website_url_verification' => 'http://evil.example',
        ];

        $result = BotDefenseGuard::verifySubmission($payload, $ip);
        $this->assertFalse($result['passed']);
        $this->assertSame('HONEYTRAP_TRIGGERED', $result['reason']);
    }

    public function testIpSubnetExtraction(): void
    {
        $this->assertSame('203.0.113.0/24', BotDefenseGuard::extractIpSubnet('203.0.113.45'));
        $this->assertSame('198.51.100.0/24', BotDefenseGuard::extractIpSubnet('198.51.100.1'));
    }
}
