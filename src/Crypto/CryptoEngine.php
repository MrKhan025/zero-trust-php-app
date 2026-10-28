<?php

declare(strict_types=1);

namespace ZeroTrust\Crypto;

use RuntimeException;
use ZeroTrust\Core\Config;

/**
 * High-Assurance Cryptographic Engine for Zero-Trust Data Protection.
 *
 * Implements:
 * - Authenticated Encryption with Associated Data (AEAD):
 *   Uses libsodium XChaCha20-Poly1305-IETF (192-bit nonce, 128-bit Poly1305 MAC)
 *   with automatic fallback to OpenSSL AES-256-GCM (96-bit IV, 128-bit GCM Tag).
 * - HKDF-SHA256 Context-Bound Subkey Derivation (RFC 5869).
 * - Argon2id Memory-Hard Password Hashing with pre-hash HMAC-SHA256 Peppering.
 * - Constant-Time String & MAC Comparisons (`hash_equals`) to eliminate timing side-channels.
 * - Explicit Memory Zeroization for sensitive key material.
 */
final class CryptoEngine
{
    private const VERSION_XCHACHA20 = 'v1:xchacha20';
    private const VERSION_AES256GCM = 'v1:aes256gcm';

    /**
     * Derives a dedicated 256-bit cryptographic subkey using HKDF-SHA256 (RFC 5869)
     * so the master key is never used directly across different contexts.
     */
    public static function deriveSubkey(string $context, string $salt = ''): string
    {
        $masterKey = Config::getKeyBytes('ZT_MASTER_ENCRYPTION_KEY');
        $subkey = hash_hkdf('sha256', $masterKey, 32, 'ZeroTrust-SubKey:' . $context, $salt);
        self::wipe($masterKey);
        return $subkey;
    }

    /**
     * Encrypts plaintext using AEAD (XChaCha20-Poly1305-IETF or AES-256-GCM) with
     * mandatory Associated Authenticated Data (AAD) binding.
     */
    public static function encrypt(string $plaintext, string $associatedData = '', string $keyContext = 'default'): string
    {
        $subkey = self::deriveSubkey($keyContext);

        try {
            if (function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                    $plaintext,
                    $associatedData,
                    $nonce,
                    $subkey
                );
                return self::VERSION_XCHACHA20 . ':' . base64_encode($nonce) . ':' . base64_encode($ciphertext);
            }

            // Fallback to OpenSSL AES-256-GCM if libsodium is unavailable
            $iv = random_bytes(12);
            $tag = '';
            $ciphertext = openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $subkey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $associatedData,
                16
            );

            if ($ciphertext === false || strlen($tag) !== 16) {
                throw new RuntimeException('AEAD encryption failure.');
            }

            return self::VERSION_AES256GCM . ':' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($ciphertext);
        } finally {
            self::wipe($subkey);
        }
    }

    /**
     * Decrypts and authenticates an AEAD payload. Throws RuntimeException if the
     * authentication tag, nonce, or Associated Authenticated Data (AAD) has been tampered with.
     */
    public static function decrypt(string $payload, string $associatedData = '', string $keyContext = 'default'): string
    {
        $subkey = self::deriveSubkey($keyContext);

        try {
            if (str_starts_with($payload, self::VERSION_XCHACHA20 . ':')) {
                $parts = explode(':', $payload, 4);
                if (count($parts) !== 4) {
                    throw new RuntimeException('Malformed XChaCha20-Poly1305 payload.');
                }
                $nonce = base64_decode($parts[2], true);
                $ciphertext = base64_decode($parts[3], true);

                if ($nonce === false || $ciphertext === false || strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
                    throw new RuntimeException('Invalid XChaCha20-Poly1305 nonce or ciphertext.');
                }

                $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $ciphertext,
                    $associatedData,
                    $nonce,
                    $subkey
                );

                if ($plaintext === false) {
                    throw new RuntimeException('AEAD authentication failed: Ciphertext or AAD tampered.');
                }
                return $plaintext;
            }

            if (str_starts_with($payload, self::VERSION_AES256GCM . ':')) {
                $parts = explode(':', $payload, 5);
                if (count($parts) !== 5) {
                    throw new RuntimeException('Malformed AES-256-GCM payload.');
                }
                $iv = base64_decode($parts[2], true);
                $tag = base64_decode($parts[3], true);
                $ciphertext = base64_decode($parts[4], true);

                if ($iv === false || $tag === false || $ciphertext === false || strlen($iv) !== 12 || strlen($tag) !== 16) {
                    throw new RuntimeException('Invalid AES-256-GCM parameters.');
                }

                $plaintext = openssl_decrypt(
                    $ciphertext,
                    'aes-256-gcm',
                    $subkey,
                    OPENSSL_RAW_DATA,
                    $iv,
                    $tag,
                    $associatedData
                );

                if ($plaintext === false) {
                    throw new RuntimeException('AEAD authentication failed: Ciphertext or AAD tampered.');
                }
                return $plaintext;
            }

            throw new RuntimeException('Unsupported cryptographic envelope version.');
        } finally {
            self::wipe($subkey);
        }
    }

    /**
     * Hashes a password using HMAC-SHA256 Peppering followed by Argon2id memory-hard hashing.
     * Even if the database is exfiltrated, offline GPU/ASIC cracking is infeasible without
     * the hardware/environment-isolated `ZT_AUTH_PEPPER_SECRET`.
     */
    public static function hashPassword(string $password): string
    {
        $pepper = Config::getKeyBytes('ZT_AUTH_PEPPER_SECRET');
        $peppered = hash_hmac('sha256', $password, $pepper, false);
        self::wipe($pepper);

        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        if (defined('PASSWORD_ARGON2ID')) {
            $options = ['memory_cost' => 65536, 'time_cost' => 4];
            if (defined('PASSWORD_ARGON2_DEFAULT_THREADS') && PHP_OS_FAMILY === 'Linux') {
                $options['threads'] = 2;
            }
        } else {
            $options = ['cost' => 12];
        }

        try {
            try {
                return password_hash($peppered, $algo, $options);
            } catch (\ValueError) {
                unset($options['threads']);
                return password_hash($peppered, $algo, $options);
            }
        } finally {
            self::wipe($peppered);
        }
    }

    /**
     * Verifies a password in constant time against an Argon2id + HMAC-SHA256 peppered hash.
     */
    public static function verifyPassword(string $password, string $storedHash): bool
    {
        $pepper = Config::getKeyBytes('ZT_AUTH_PEPPER_SECRET');
        $peppered = hash_hmac('sha256', $password, $pepper, false);
        self::wipe($pepper);

        try {
            return password_verify($peppered, $storedHash);
        } finally {
            self::wipe($peppered);
        }
    }

    /**
     * Performs a dummy Argon2id verification when a user account does not exist,
     * equalizing response latency so attackers and AI timing probes cannot enumerate usernames.
     */
    public static function mitigateTimingEnumeration(string $inputPassword): void
    {
        // Pre-computed valid Argon2id hash for timing equalization
        $dummyHash = '$argon2id$v=19$m=65536,t=4,p=2$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
        self::verifyPassword($inputPassword, $dummyHash);
    }

    /**
     * Computes a deterministic blind index (HMAC-SHA256) for searchable encrypted fields (e.g., email).
     */
    public static function blindIndex(string $value, string $domain = 'email'): string
    {
        $subkey = self::deriveSubkey('blind-index:' . $domain);
        $normalized = strtolower(trim($value));
        $index = hash_hmac('sha256', $normalized, $subkey);
        self::wipe($subkey);
        return $index;
    }

    /**
     * Signs a message or token payload using the dedicated signing key.
     */
    public static function sign(string $message, string $purpose = 'token'): string
    {
        $signingKey = Config::getKeyBytes('ZT_TOKEN_SIGNING_KEY');
        $contextKey = hash_hkdf('sha256', $signingKey, 32, 'ZeroTrust-Sign:' . $purpose);
        self::wipe($signingKey);

        $mac = hash_hmac('sha256', $message, $contextKey);
        self::wipe($contextKey);
        return $mac;
    }

    /**
     * Verifies a message signature in strict constant time (`hash_equals`).
     */
    public static function verifySignature(string $message, string $signature, string $purpose = 'token'): bool
    {
        $expected = self::sign($message, $purpose);
        return hash_equals($expected, $signature);
    }

    /**
     * Generates a cryptographically secure UUIDv4 identifier.
     */
    public static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /**
     * Zeroizes sensitive string buffers in memory while preserving a string type.
     */
    public static function wipe(string &$secret): void
    {
        $length = strlen($secret);
        for ($i = 0; $i < $length; $i++) {
            $secret[$i] = "\0";
        }
        $secret = '';
    }
}
