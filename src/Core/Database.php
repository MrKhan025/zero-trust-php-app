<?php

declare(strict_types=1);

namespace ZeroTrust\Core;

use PDO;
use PDOException;
use RuntimeException;

/**
 * Hardened PDO Database Manager with Strict Prepared Statements & Automatic Schema Provisioning.
 * Zero raw SQL interpolation is permitted; emulated prepares are strictly disabled.
 */
final class Database
{
    private static ?PDO $pdo = null;

    public static function connection(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $driver = Config::get('DB_CONNECTION', 'sqlite');
        try {
            if ($driver === 'sqlite') {
                $relativePath = Config::get('DB_SQLITE_PATH', 'storage/database/zerotrust.sqlite');
                $fullPath = Config::basePath($relativePath ?? 'storage/database/zerotrust.sqlite');
                $dir = dirname($fullPath);
                if (!is_dir($dir)) {
                    mkdir($dir, 0750, true);
                }
                $dsn = 'sqlite:' . $fullPath;
                self::$pdo = new PDO($dsn, null, null, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]);
                self::$pdo->exec('PRAGMA journal_mode = WAL;');
                self::$pdo->exec('PRAGMA foreign_keys = ON;');
                self::$pdo->exec('PRAGMA secure_delete = ON;');
            } else {
                $dsn = (string) Config::get('DB_DSN', '');
                $user = Config::get('DB_USERNAME');
                $pass = Config::get('DB_PASSWORD');
                self::$pdo = new PDO($dsn, $user, $pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]);
            }
        } catch (PDOException $e) {
            throw new RuntimeException('Database connection failed due to internal policy barrier.');
        }

        self::migrate(self::$pdo);
        return self::$pdo;
    }

    /**
     * Allows injecting an in-memory PDO instance during automated security testing.
     */
    public static function setConnection(PDO $pdo): void
    {
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        self::$pdo = $pdo;
        self::migrate(self::$pdo);
    }

    private static function migrate(PDO $pdo): void
    {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL UNIQUE,
                email_hash TEXT NOT NULL UNIQUE,
                email_encrypted TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                totp_secret_encrypted TEXT DEFAULT NULL,
                recovery_codes_json TEXT DEFAULT NULL,
                account_locked_until INTEGER DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                last_login_at INTEGER DEFAULT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS zt_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                device_fingerprint_hash TEXT NOT NULL,
                ip_subnet_hash TEXT NOT NULL,
                user_agent_hash TEXT NOT NULL,
                mfa_verified INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL DEFAULT 0,
                issued_at INTEGER NOT NULL,
                last_rotated_at INTEGER NOT NULL,
                last_active_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                bucket_key TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                window_started_at INTEGER NOT NULL,
                locked_until INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce_hash TEXT PRIMARY KEY,
                purpose TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                user_id INTEGER DEFAULT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                context_encrypted TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );
        ");
    }
}
