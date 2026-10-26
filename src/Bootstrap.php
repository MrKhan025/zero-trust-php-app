<?php

declare(strict_types=1);

namespace ZeroTrust;

/**
 * Zero-Trust Bootstrap & Self-Contained PSR-4 Autoloader.
 * Ensures the application runs out-of-the-box even in minimal container environments
 * where Composer vendor autoloading has not been executed.
 */
final class Bootstrap
{
    private static bool $initialized = false;

    public static function init(string $basePath): void
    {
        if (self::$initialized) {
            return;
        }

        // 1. Register Composer autoloader if present, else fallback to strict PSR-4 autoloader
        $composerAutoload = $basePath . '/vendor/autoload.php';
        if (is_file($composerAutoload)) {
            require_once $composerAutoload;
        } else {
            spl_autoload_register(static function (string $class) use ($basePath): void {
                $prefix = 'ZeroTrust\\';
                if (!str_starts_with($class, $prefix)) {
                    return;
                }
                $relativeClass = substr($class, strlen($prefix));
                $file = $basePath . '/src/' . str_replace('\\', '/', $relativeClass) . '.php';
                if (is_file($file)) {
                    require_once $file;
                }
            });
        }

        // 2. Load .env configuration file if present, fallback to .env.example defaults
        $envFile = is_file($basePath . '/.env')
            ? $basePath . '/.env'
            : $basePath . '/.env.example';

        \ZeroTrust\Core\Config::load($envFile, $basePath);

        // 3. Enforce strict PHP runtime security settings
        ini_set('display_errors', \ZeroTrust\Core\Config::getBool('APP_DEBUG', false) ? '1' : '0');
        ini_set('display_startup_errors', '0');
        ini_set('log_errors', '1');
        ini_set('expose_php', '0');
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');

        date_default_timezone_set((string) \ZeroTrust\Core\Config::get('APP_TIMEZONE', 'UTC'));

        self::$initialized = true;
    }
}
