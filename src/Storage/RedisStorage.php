<?php

declare(strict_types=1);

namespace ZeroTrust\Storage;

use Redis;
use RuntimeException;

final class RedisStorage implements StorageInterface
{
    private Redis $redis;

    public function __construct(
        string $host = '127.0.0.1',
        int $port = 6379,
        string $prefix = 'zt:',
        ?string $password = null
    ) {
        if (!extension_loaded('redis')) {
            throw new RuntimeException('The redis PHP extension is required for RedisStorage.');
        }

        $this->redis = new Redis();
        if (!$this->redis->connect($host, $port, 1.5)) {
            throw new RuntimeException("Unable to connect to Redis at {$host}:{$port}");
        }

        if ($password !== null && $password !== '') {
            $this->redis->auth($password);
        }

        $this->redis->setOption(Redis::OPT_PREFIX, $prefix);
    }

    public function get(string $key): ?string
    {
        $val = $this->redis->get($key);
        return $val === false ? null : (string) $val;
    }

    public function set(string $key, string $value, int $ttlSeconds = 0): void
    {
        if ($ttlSeconds > 0) {
            $this->redis->setex($key, $ttlSeconds, $value);
        } else {
            $this->redis->set($key, $value);
        }
    }

    public function delete(string $key): void
    {
        $this->redis->del($key);
    }

    public function increment(string $key, int $ttlSeconds = 0): int
    {
        $val = (int) $this->redis->incr($key);
        if ($ttlSeconds > 0 && $val === 1) {
            $this->redis->expire($key, $ttlSeconds);
        }
        return $val;
    }

    public function exists(string $key): bool
    {
        return (bool) $this->redis->exists($key);
    }
}
