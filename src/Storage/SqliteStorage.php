<?php

declare(strict_types=1);

namespace ZeroTrust\Storage;

use PDO;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

final class SqliteStorage implements StorageInterface
{
    private static function connection(): PDO
    {
        $pdo = Database::connection();
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS kv_store (
                key_hash TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER NOT NULL DEFAULT 0
            )
        ');
        return $pdo;
    }

    public function get(string $key): ?string
    {
        $pdo = self::connection();
        $hash = CryptoEngine::blindIndex($key, 'storage');
        $stmt = $pdo->prepare('SELECT value, expires_at FROM kv_store WHERE key_hash = :h LIMIT 1');
        $stmt->execute([':h' => $hash]);
        $row = $stmt->fetch();

        if ($row === false) {
            return null;
        }

        $expires = (int) $row['expires_at'];
        if ($expires > 0 && $expires < time()) {
            $this->delete($key);
            return null;
        }

        return (string) $row['value'];
    }

    public function set(string $key, string $value, int $ttlSeconds = 0): void
    {
        $pdo = self::connection();
        $now = time();
        $pdo->prepare('DELETE FROM kv_store WHERE expires_at > 0 AND expires_at < :now')
            ->execute([':now' => $now]);

        $hash = CryptoEngine::blindIndex($key, 'storage');
        $expires = $ttlSeconds > 0 ? $now + $ttlSeconds : 0;

        $stmt = $pdo->prepare('
            INSERT INTO kv_store (key_hash, value, expires_at)
            VALUES (:h, :v, :e)
            ON CONFLICT(key_hash) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
        ');
        $stmt->execute([':h' => $hash, ':v' => $value, ':e' => $expires]);
    }

    public function delete(string $key): void
    {
        $pdo = self::connection();
        $hash = CryptoEngine::blindIndex($key, 'storage');
        $pdo->prepare('DELETE FROM kv_store WHERE key_hash = :h')->execute([':h' => $hash]);
    }

    public function increment(string $key, int $ttlSeconds = 0): int
    {
        $pdo = self::connection();
        $hash = CryptoEngine::blindIndex($key, 'storage');
        $now = time();

        $stmt = $pdo->prepare('SELECT value, expires_at FROM kv_store WHERE key_hash = :h LIMIT 1');
        $stmt->execute([':h' => $hash]);
        $row = $stmt->fetch();

        if ($row === false || ((int) $row['expires_at'] > 0 && (int) $row['expires_at'] < $now)) {
            $this->set($key, '1', $ttlSeconds);
            return 1;
        }

        $new = ((int) $row['value']) + 1;
        $upd = $pdo->prepare('UPDATE kv_store SET value = :v WHERE key_hash = :h');
        $upd->execute([':v' => (string) $new, ':h' => $hash]);

        return $new;
    }

    public function exists(string $key): bool
    {
        return $this->get($key) !== null;
    }
}
