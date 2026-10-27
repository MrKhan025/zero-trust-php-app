<?php

declare(strict_types=1);

namespace ZeroTrust\Storage;

interface StorageInterface
{
    public function get(string $key): ?string;

    public function set(string $key, string $value, int $ttlSeconds = 0): void;

    public function delete(string $key): void;

    /** Atomic increment. Returns the new value. */
    public function increment(string $key, int $ttlSeconds = 0): int;

    public function exists(string $key): bool;
}
