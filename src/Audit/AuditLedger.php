<?php

declare(strict_types=1);

namespace ZeroTrust\Audit;

use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

/**
 * Tamper-Evident Cryptographic Hash-Chained Security Audit Ledger & Telemetry Exporter.
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

            if (!hash_equals($expectedPrevHash, $prevHash)) {
                return [
                    'valid' => false,
                    'total_entries' => $count,
                    'broken_at_id' => $id,
                    'error' => "Chain link broken at entry #{$id}: prev_hash mismatch (possible row deletion or reordering).",
                ];
            }

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

    /**
     * Computes real-time anonymized security telemetry for Prometheus / OpenTelemetry & JSON dashboards.
     *
     * @return array{
     *     audit_chain_valid: int,
     *     audit_entries_total: int,
     *     registered_identities_total: int,
     *     active_sessions_total: int,
     *     revoked_sessions_total: int,
     *     waf_blocks_total: int,
     *     pow_failures_total: int,
     *     critical_events_total: int
     * }
     */
    public static function getSecurityMetrics(): array
    {
        $pdo = Database::connection();
        $chain = self::verifyChainIntegrity();
        $now = time();

        $usersCount = (int) ($pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() ?: 0);

        $activeStmt = $pdo->prepare('SELECT COUNT(*) FROM zt_sessions WHERE revoked = 0 AND expires_at > :now');
        $activeStmt->execute([':now' => $now]);
        $activeSessions = (int) ($activeStmt->fetchColumn() ?: 0);

        $revokedSessions = (int) ($pdo->query('SELECT COUNT(*) FROM zt_sessions WHERE revoked = 1')->fetchColumn() ?: 0);
        $wafBlocks = (int) ($pdo->query("SELECT COUNT(*) FROM audit_ledger WHERE event_type = 'WAF_PAYLOAD_BLOCKED'")->fetchColumn() ?: 0);
        $powFailures = (int) ($pdo->query("SELECT COUNT(*) FROM audit_ledger WHERE event_type IN ('AUTH_POW_FAILED', 'REGISTER_BOT_DEFENSE_BLOCKED')")->fetchColumn() ?: 0);
        $criticalEvents = (int) ($pdo->query("SELECT COUNT(*) FROM audit_ledger WHERE severity = 'CRITICAL'")->fetchColumn() ?: 0);

        return [
            'audit_chain_valid' => $chain['valid'] ? 1 : 0,
            'audit_entries_total' => $chain['total_entries'],
            'registered_identities_total' => $usersCount,
            'active_sessions_total' => $activeSessions,
            'revoked_sessions_total' => $revokedSessions,
            'waf_blocks_total' => $wafBlocks,
            'pow_failures_total' => $powFailures,
            'critical_events_total' => $criticalEvents,
        ];
    }

    /**
     * Formats security metrics in standard Prometheus text exposition format (0.0.4).
     */
    public static function formatPrometheusMetrics(): string
    {
        $m = self::getSecurityMetrics();
        $lines = [
            '# HELP zerotrust_audit_chain_valid Whether the cryptographic hash-chained audit ledger is intact (1 = valid, 0 = tampered).',
            '# TYPE zerotrust_audit_chain_valid gauge',
            'zerotrust_audit_chain_valid ' . $m['audit_chain_valid'],
            '# HELP zerotrust_audit_entries_total Total number of cryptographic blocks in the audit ledger.',
            '# TYPE zerotrust_audit_entries_total counter',
            'zerotrust_audit_entries_total ' . $m['audit_entries_total'],
            '# HELP zerotrust_registered_identities_total Total provisioned Zero-Trust identities.',
            '# TYPE zerotrust_registered_identities_total gauge',
            'zerotrust_registered_identities_total ' . $m['registered_identities_total'],
            '# HELP zerotrust_active_sessions_total Currently active, non-expired Zero-Trust sessions.',
            '# TYPE zerotrust_active_sessions_total gauge',
            'zerotrust_active_sessions_total ' . $m['active_sessions_total'],
            '# HELP zerotrust_revoked_sessions_total Total sessions revoked by logout or adaptive risk policy.',
            '# TYPE zerotrust_revoked_sessions_total counter',
            'zerotrust_revoked_sessions_total ' . $m['revoked_sessions_total'],
            '# HELP zerotrust_waf_blocks_total Total malicious payloads blocked by WafMiddleware.',
            '# TYPE zerotrust_waf_blocks_total counter',
            'zerotrust_waf_blocks_total ' . $m['waf_blocks_total'],
            '# HELP zerotrust_pow_failures_total Total failed Proof-of-Work or honeytrap bot challenges.',
            '# TYPE zerotrust_pow_failures_total counter',
            'zerotrust_pow_failures_total ' . $m['pow_failures_total'],
            '# HELP zerotrust_critical_events_total Total CRITICAL severity events recorded in the ledger.',
            '# TYPE zerotrust_critical_events_total counter',
            'zerotrust_critical_events_total ' . $m['critical_events_total'],
            '',
        ];

        return implode("\n", $lines);
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
