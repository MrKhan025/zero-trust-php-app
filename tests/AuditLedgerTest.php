<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Audit\AuditLedger;
use ZeroTrust\Core\Database;
use PDO;

final class AuditLedgerTest extends TestCase
{
    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        Database::setConnection($pdo);
    }

    public function testChainIntegrityAfterMultipleEntries(): void
    {
        AuditLedger::record('TEST_EVENT_1', 'INFO', '127.0.0.1', null, 10, ['foo' => 'bar']);
        AuditLedger::record('TEST_EVENT_2', 'WARNING', '127.0.0.1', 1, 40, ['action' => 'login']);
        AuditLedger::record('TEST_EVENT_3', 'CRITICAL', '10.0.0.5', 2, 90, ['reason' => 'hijack']);

        $status = AuditLedger::verifyChainIntegrity();
        $this->assertTrue($status['valid']);
        $this->assertGreaterThanOrEqual(3, $status['total_entries']);
    }

    public function testTamperingIsDetected(): void
    {
        AuditLedger::record('CLEAN_EVENT', 'INFO', '127.0.0.1', null, 0, []);

        $pdo = Database::connection();
        $pdo->exec("UPDATE audit_ledger SET entry_hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = 1");

        $status = AuditLedger::verifyChainIntegrity();
        $this->assertFalse($status['valid']);
    }
}
