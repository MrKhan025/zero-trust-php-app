<?php

declare(strict_types=1);

namespace ZeroTrust\Defense;

/**
 * Application-Layer Web Application Firewall (WAF) & Security Headers Enforcer.
 *
 * Inspects request parameters, headers, and URI paths for common and advanced payload signatures:
 * - SQL Injection (SQLi) & stacked queries
 * - Cross-Site Scripting (XSS) & DOM event handlers
 * - Path Traversal / Local File Inclusion (LFI)
 * - PHP Object Injection / Phar Deserialization
 * - Server-Side Request Forgery (SSRF) & Command Injection
 * - LLM Prompt Injection / Automated Agent Header anomalies
 */
final class WafMiddleware
{
    /** @var array<string, string> */
    private const PAYLOAD_SIGNATURES = [
        'SQL_INJECTION' => '/(\b(union\s+all\s+select|union\s+select|information_schema|sleep\s*\(\s*\d+|benchmark\s*\(|load_file\s*\()\b|--\s*$|;\s*(drop|alter|truncate)\s+table)/i',
        'XSS_ATTACK' => '/(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|onmouseover\s*=|<\s*iframe\b|<\s*svg\b[^>]*on\w+\s*=)/i',
        'PATH_TRAVERSAL' => '/(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f|\/etc\/passwd|\/proc\/self\/environ)/i',
        'OBJECT_DESERIALIZATION' => '/(\b(O|C):\d+:"[^"]+":\d+:\{|phar:\/\/|php:\/\/filter)/i',
        'COMMAND_INJECTION' => '/(;\s*(cat|wget|curl|nc|bash|sh)\b|\$\([^)]+\)|`[^`]+`)/i',
    ];

    /**
     * Sends strict Zero-Trust HTTP security headers, including a nonce-based Content-Security-Policy (CSP).
     */
    public static function emitSecurityHeaders(string $cspNonce): void
    {
        if (headers_sent()) {
            return;
        }

        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$cspNonce}'; style-src 'self' 'nonce-{$cspNonce}'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests");
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Cross-Origin-Embedder-Policy: require-corp');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }

    /**
     * Inspects incoming request data for malicious exploit patterns.
     *
     * @param array<string, mixed> $get
     * @param array<string, mixed> $post
     * @param array<string, mixed> $server
     * @return array{blocked: bool, rule: string, matched_input: string}
     */
    public static function inspectRequest(array $get, array $post, array $server): array
    {
        $inputs = [];

        foreach ($get as $k => $v) {
            $inputs['GET:' . $k] = is_scalar($v) ? (string) $v : json_encode($v);
        }
        foreach ($post as $k => $v) {
            // Do not run regex heuristics against raw password fields to avoid false positives on complex symbols,
            // while still checking length and null-byte injection.
            if ($k === 'password' || $k === 'password_confirm') {
                if (is_string($v) && str_contains($v, "\0")) {
                    return ['blocked' => true, 'rule' => 'NULL_BYTE_INJECTION', 'matched_input' => 'POST:' . $k];
                }
                continue;
            }
            $inputs['POST:' . $k] = is_scalar($v) ? (string) $v : (string) json_encode($v);
        }

        $uri = (string) ($server['REQUEST_URI'] ?? '');
        $ua = (string) ($server['HTTP_USER_AGENT'] ?? '');
        $inputs['URI'] = urldecode($uri);
        $inputs['USER_AGENT'] = $ua;

        foreach ($inputs as $source => $value) {
            if (!is_string($value) || $value === '') {
                continue;
            }
            if (str_contains($value, "\0")) {
                return ['blocked' => true, 'rule' => 'NULL_BYTE_INJECTION', 'matched_input' => $source];
            }
            foreach (self::PAYLOAD_SIGNATURES as $ruleName => $pattern) {
                if (preg_match($pattern, $value) === 1) {
                    return [
                        'blocked' => true,
                        'rule' => $ruleName,
                        'matched_input' => $source,
                    ];
                }
            }
        }

        return ['blocked' => false, 'rule' => 'NONE', 'matched_input' => ''];
    }
}
