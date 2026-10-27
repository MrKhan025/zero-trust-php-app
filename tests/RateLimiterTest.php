<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Defense\RateLimiter;
use ZeroTrust\Storage\StorageFactory;
use ZeroTrust\Storage\SqliteStorage;
use ZeroTrust\Core\Database;
use PDO;

final class RateLimiterTest extends TestCase
{
    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        Database::setConnection($pdo);
        StorageFactory::setInstance(new SqliteStorage());
    }

    public function testAllowsUnderThreshold(): void
    {
        $result = RateLimiter::check('test_action', 'user-1');
        $this->assertTrue($result['allowed']);
    }

    public function testLocksAfterMaxAttempts(): void
    {
        $action = 'test_lock_' . bin2hex(random_bytes(4));
        $id = 'attacker-ip';

        for ($i = 0; $i < 6; $i++) {
            RateLimiter::hit($action, $id);
        }

        $result = RateLimiter::check($action, $id);
        $this->assertFalse($result['allowed']);
        $this->assertGreaterThan(0, $result['retry_after']);
    }

    public function testClearResetsBucket(): void
    {
        $action = 'test_clear_' . bin2hex(random_bytes(4));
        $id = 'user-2';

        RateLimiter::hit($action, $id);
        RateLimiter::hit($action, $id);
        RateLimiter::clear($action, $id);

        $result = RateLimiter::check($action, $id);
        $this->assertTrue($result['allowed']);
    }
}
