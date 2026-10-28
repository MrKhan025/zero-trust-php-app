<?php

declare(strict_types=1);

namespace ZeroTrust\Core;

use RuntimeException;

/**
 * Immutable Environment & Security Policy Configuration Manager.
 */
final class Config
{
    /** @var array<string, string> */
    private static array $items = [];
    private static string $basePath = '';

    public static function load(string $envFilePath, string $basePath): void
    {
        self::$basePath = rtrim($basePath, '/\\');

        if (is_file($envFilePath) && is_readable($envFilePath)) {
            $lines = file($envFilePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                foreach ($lines as $line) {
                    $trimmed = trim($line);
                    if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                        continue;
                    }
                    $parts = explode('=', $trimmed, 2);
                    if (count($parts) !== 2) {
                        continue;
                    }
                    $key = trim($parts[0]);
                    $value = trim($parts[1]);
                    $value = trim($value, "\"'");
                    self::$items[$key] = $value;
                }
            }
        }

        // Allow real OS environment variables to override file defaults
        foreach ($_ENV as $k => $v) {
            if (is_string($v)) {
                self::$items[$k] = $v;
            }
        }
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        $envVal = getenv($key);
        if (is_string($envVal) && $envVal !== '') {
            return $envVal;
        }
        return self::$items[$key] ?? $default;
    }

    public static function getInt(string $key, int $default = 0): int
    {
        $val = self::get($key);
        return ($val !== null && is_numeric($val)) ? (int) $val : $default;
    }

    public static function getBool(string $key, bool $default = false): bool
    {
        $val = self::get($key);
        if ($val === null) {
            return $default;
        }
        return in_array(strtolower($val), ['true', '1', 'yes', 'on'], true);
    }

    public static function getKeyBytes(string $keyName): string
    {
        $hex = self::get($keyName);
        if ($hex === null || strlen($hex) < 64 || !ctype_xdigit($hex)) {
            throw new RuntimeException("Invalid or missing 256-bit hex cryptographic key for: {$keyName}");
        }
        $binary = hex2bin(substr($hex, 0, 64));
        if ($binary === false || strlen($binary) !== 32) {
            throw new RuntimeException("Failed to decode 256-bit key for: {$keyName}");
        }
        return $binary;
    }

    public static function basePath(string $subPath = ''): string
    {
        return $subPath === ''
            ? self::$basePath
            : self::$basePath . '/' . ltrim(str_replace('\\', '/', $subPath), '/');
    }
}
