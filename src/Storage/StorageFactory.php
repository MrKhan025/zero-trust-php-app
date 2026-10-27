<?php

declare(strict_types=1);

namespace ZeroTrust\Storage;

use ZeroTrust\Core\Config;

final class StorageFactory
{
    private static ?StorageInterface $instance = null;

    public static function get(): StorageInterface
    {
        if (self::$instance !== null) {
            return self::$instance;
        }

        $driver = strtolower((string) Config::get('ZT_STORAGE_DRIVER', 'sqlite'));

        if ($driver === 'redis') {
            $host = Config::get('ZT_REDIS_HOST', '127.0.0.1') ?? '127.0.0.1';
            $port = Config::getInt('ZT_REDIS_PORT', 6379);
            $password = Config::get('ZT_REDIS_PASSWORD');
            self::$instance = new RedisStorage($host, $port, 'zt:', $password);
        } else {
            self::$instance = new SqliteStorage();
        }

        return self::$instance;
    }

    /** Useful for tests */
    public static function setInstance(?StorageInterface $instance): void
    {
        self::$instance = $instance;
    }
}
