<?php

declare(strict_types=1);

namespace ZeroTrust\Storage;

use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;

final class SqliteStorage implements StorageInterface
{
    public function get(string $key): ?string
    {
        $pdo = Database::connection();
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
        $pdo = Database::connection();
        $hash = CryptoEngine::blindIndex($key, 'storage');
        $expires = $ttlSeconds > 0 ? time() + $ttlSeconds : 0;

        $stmt = $pdo->prepare('
            INSERT INTO kv_store (key_hash, value, expires_at)
            VALUES (:h, :v, :e)
            ON CONFLICT(key_hash) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
        ');
        $stmt->execute([':h' => $hash, ':v' => $value, ':e' => $expires]);
    }

    public function delete(string $key): void
    {
        $pdo = Database::connection();
        $hash = CryptoEngine::blindIndex($key, 'storage');
        $pdo->prepare('DELETE FROM kv_store WHERE key_hash = :h')->execute([':h' => $hash]);
    }

    public function increment(string $key, int $ttlSeconds = 0): int
    {
        $current = (int) ($this->get($key) ?? '0');
        $new = $current + 1;
        $this->set($key, (string) $new, $ttlSeconds);
        return $new;
    }

    public function exists(string $key): bool
    {
        return $this->get($key) !== null;
    }
}
