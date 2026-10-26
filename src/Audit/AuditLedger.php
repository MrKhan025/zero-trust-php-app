<?php

declare(strict_types=1);

namespace ZeroTrust\Audit;

use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

/**
 * Tamper-Evident Cryptographic Hash-Chained Security Audit Ledger.
 *
 * Every security event is:
 * 1. Assigned a unique UUIDv4 `event_id`.
 * 2. Encrypted at rest using XChaCha20-Poly1305 / AES-256-GCM with the `event_id` and `event_type`
 *    bound as Associated Authenticated Data (AAD) so context cannot be swapped across rows.
 * 3. Chained via SHA-256 (`entry_hash = HMAC-SHA256(prev_hash | event_id | user_id | event_type | severity | risk_score | context_encrypted | created_at)`).
 *
 * If an attacker with direct database write access modifies, deletes, or reorders a single historical
 * log record, `AuditLedger::verifyChainIntegrity()` immediately detects the exact broken link.
 */
final class AuditLedger
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Records an immutable, encrypted, hash-chained security event in the audit ledger.
     *
     * @param array<string, mixed> $context
     */
    public static function record(
        string $eventType,
        string $severity,
        string $clientIp,
        ?int $userId = null,
        int $riskScore = 0,
        array $context = []
    ): string {
        $pdo = Database::connection();
        $eventId = CryptoEngine::uuidV4();
        $now = time();
        $ipHash = CryptoEngine::blindIndex($clientIp, 'audit-ip');

        $jsonContext = json_encode($context, JSON_THROW_ON_ERROR);
        $aad = $eventId . '|' . $eventType . '|' . $severity;
        $encryptedContext = CryptoEngine::encrypt($jsonContext, $aad, 'audit-ledger');

        // Fetch previous entry hash
        $stmt = $pdo->query('SELECT entry_hash FROM audit_ledger ORDER BY id DESC LIMIT 1');
        $lastRow = $stmt !== false ? $stmt->fetch() : false;
        $prevHash = is_array($lastRow) && isset($lastRow['entry_hash'])
            ? (string) $lastRow['entry_hash']
            : self::GENESIS_HASH;

        $entryHash = self::computeEntryHash(
            $prevHash,
            $eventId,
            $userId,
            $eventType,
            $severity,
            $ipHash,
            $riskScore,
            $encryptedContext,
            $now
        );

        $insert = $pdo->prepare('
            INSERT INTO audit_ledger (
                event_id, user_id, event_type, severity, ip_hash,
                risk_score, context_encrypted, prev_hash, entry_hash, created_at
            ) VALUES (
                :event_id, :user_id, :event_type, :severity, :ip_hash,
                :risk_score, :context_encrypted, :prev_hash, :entry_hash, :created_at
            )
        ');

        $insert->execute([
            ':event_id' => $eventId,
            ':user_id' => $userId,
            ':event_type' => $eventType,
            ':severity' => $severity,
            ':ip_hash' => $ipHash,
            ':risk_score' => $riskScore,
            ':context_encrypted' => $encryptedContext,
            ':prev_hash' => $prevHash,
            ':entry_hash' => $entryHash,
            ':created_at' => $now,
        ]);

        return $eventId;
    }

    /**
     * Verifies the cryptographic integrity of the entire audit ledger from the Genesis block
     * and authenticates the AEAD tag of every encrypted context payload.
     *
     * @return array{valid: bool, total_entries: int, broken_at_id: ?int, error: ?string}
     */
    public static function verifyChainIntegrity(): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->query('SELECT * FROM audit_ledger ORDER BY id ASC');
        $rows = $stmt !== false ? $stmt->fetchAll() : [];

        $expectedPrevHash = self::GENESIS_HASH;
        $count = 0;

        foreach ($rows as $row) {
            $count++;
            $id = (int) $row['id'];
            $eventId = (string) $row['event_id'];
            $userId = $row['user_id'] !== null ? (int) $row['user_id'] : null;
            $eventType = (string) $row['event_type'];
            $severity = (string) $row['severity'];
            $ipHash = (string) $row['ip_hash'];
            $riskScore = (int) $row['risk_score'];
            $encryptedContext = (string) $row['context_encrypted'];
            $prevHash = (string) $row['prev_hash'];
            $entryHash = (string) $row['entry_hash'];
            $createdAt = (int) $row['created_at'];

            // 1. Verify chain link to previous block
            if (!hash_equals($expectedPrevHash, $prevHash)) {
                return [
                    'valid' => false,
                    'total_entries' => $count,
                    'broken_at_id' => $id,
                    'error' => "Chain link broken at entry #{$id}: prev_hash mismatch (possible row deletion or reordering).",
                ];
            }

            // 2. Recompute and verify HMAC-SHA256 entry hash
            $recomputed = self::computeEntryHash(
                $prevHash,
                $eventId,
                $userId,
                $eventType,
                $severity,
                $ipHash,
                $riskScore,
                $encryptedContext,
                $createdAt
            );

            if (!hash_equals($recomputed, $entryHash)) {
                return [
                    'valid' => false,
                    'total_entries' => $count,
                    'broken_at_id' => $id,
                    'error' => "Cryptographic signature mismatch at entry #{$id}: record fields were modified.",
                ];
            }

            // 3. Verify AEAD decryption & Associated Data (AAD) integrity
            try {
                $aad = $eventId . '|' . $eventType . '|' . $severity;
                CryptoEngine::decrypt($encryptedContext, $aad, 'audit-ledger');
            } catch (\Throwable $e) {
                return [
                    'valid' => false,
                    'total_entries' => $count,
                    'broken_at_id' => $id,
                    'error' => "AEAD payload authentication failed at entry #{$id}: " . $e->getMessage(),
                ];
            }

            $expectedPrevHash = $entryHash;
        }

        return [
            'valid' => true,
            'total_entries' => $count,
            'broken_at_id' => null,
            'error' => null,
        ];
    }

    /**
     * Retrieves and decrypts the most recent N audit log entries for the security dashboard.
     *
     * @return list<array<string, mixed>>
     */
    public static function getRecentEntries(int $limit = 15): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT * FROM audit_ledger ORDER BY id DESC LIMIT :limit');
        $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll();

        $results = [];
        foreach ($rows as $row) {
            $eventId = (string) $row['event_id'];
            $eventType = (string) $row['event_type'];
            $severity = (string) $row['severity'];
            $aad = $eventId . '|' . $eventType . '|' . $severity;

            $decryptedContext = [];
            try {
                $json = CryptoEngine::decrypt((string) $row['context_encrypted'], $aad, 'audit-ledger');
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    $decryptedContext = $decoded;
                }
            } catch (\Throwable) {
                $decryptedContext = ['error' => 'TAMPERED_OR_UNREADABLE_PAYLOAD'];
            }

            $results[] = [
                'id' => (int) $row['id'],
                'event_id' => $eventId,
                'user_id' => $row['user_id'] !== null ? (int) $row['user_id'] : null,
                'event_type' => $eventType,
                'severity' => $severity,
                'risk_score' => (int) $row['risk_score'],
                'context' => $decryptedContext,
                'prev_hash' => (string) $row['prev_hash'],
                'entry_hash' => (string) $row['entry_hash'],
                'created_at' => (int) $row['created_at'],
            ];
        }

        return $results;
    }

    private static function computeEntryHash(
        string $prevHash,
        string $eventId,
        ?int $userId,
        string $eventType,
        string $severity,
        string $ipHash,
        int $riskScore,
        string $encryptedContext,
        int $createdAt
    ): string {
        $canonical = implode('|', [
            $prevHash,
            $eventId,
            (string) ($userId ?? 'anon'),
            $eventType,
            $severity,
            $ipHash,
            (string) $riskScore,
            $encryptedContext,
            (string) $createdAt,
        ]);

        return CryptoEngine::sign($canonical, 'audit-ledger-chain');
    }
}
