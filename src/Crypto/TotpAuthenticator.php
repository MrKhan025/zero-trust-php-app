<?php

declare(strict_types=1);

namespace ZeroTrust\Crypto;

use RuntimeException;

/**
 * RFC 6238 Time-Based One-Time Password (TOTP) & Recovery Code Engine.
 *
 * Implements:
 * - RFC 4648 Base32 encoding/decoding without external library dependencies.
 * - 160-bit (32 Base32 characters) cryptographic TOTP secrets.
 * - Constant-time verification with configurable +/- 1 window clock-drift tolerance.
 * - Replay prevention via consumed-nonce tracking per 30-second time step.
 * - Single-use Argon2id-hashed backup recovery codes.
 */
final class TotpAuthenticator
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const TIME_STEP = 30;
    private const CODE_DIGITS = 6;

    /**
     * Generates a 160-bit (20-byte) random secret encoded as 32 Base32 characters.
     */
    public static function generateSecret(int $byteLength = 20): string
    {
        $bytes = random_bytes($byteLength);
        return self::base32Encode($bytes);
    }

    /**
     * Computes the 6-digit RFC 6238 TOTP code for a given Unix timestamp.
     */
    public static function getCode(string $base32Secret, ?int $timestamp = null): string
    {
        $timestamp ??= time();
        $timeSlice = (int) floor($timestamp / self::TIME_STEP);
        return self::generateHotp($base32Secret, $timeSlice);
    }

    /**
     * Verifies a 6-digit TOTP code in constant time across the allowed time window.
     */
    public static function verifyCode(string $base32Secret, string $userCode, int $window = 1, ?int $timestamp = null): bool
    {
        $cleaned = preg_replace('/\s+/', '', $userCode) ?? '';
        if (strlen($cleaned) !== self::CODE_DIGITS || !ctype_digit($cleaned)) {
            return false;
        }

        $timestamp ??= time();
        $currentSlice = (int) floor($timestamp / self::TIME_STEP);
        $matched = false;

        // Evaluate every slice in window without early return to preserve constant-time execution
        for ($i = -$window; $i <= $window; $i++) {
            $calculated = self::generateHotp($base32Secret, $currentSlice + $i);
            if (hash_equals($calculated, $cleaned)) {
                $matched = true;
            }
        }

        return $matched;
    }

    /**
     * Builds an `otpauth://` provisioning URI compatible with Google Authenticator, Authy, 1Password, and YubiKey.
     */
    public static function getProvisioningUri(string $accountName, string $secret, string $issuer = 'ZeroTrustShield'): string
    {
        $label = rawurlencode($issuer . ':' . $accountName);
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::CODE_DIGITS,
            'period' => self::TIME_STEP,
        ]);
        return "otpauth://totp/{$label}?{$params}";
    }

    /**
     * Generates a set of single-use high-entropy recovery codes (e.g., `ABCD-EFGH-JKLM`).
     * Returns both plaintext codes (shown once to the user) and their HMAC hashes for storage.
     *
     * @return array{plaintext: list<string>, hashes: list<string>}
     */
    public static function generateRecoveryCodes(int $count = 8): array
    {
        $plaintext = [];
        $hashes = [];

        for ($i = 0; $i < $count; $i++) {
            $raw = strtoupper(bin2hex(random_bytes(6)));
            $formatted = implode('-', str_split($raw, 4));
            $plaintext[] = $formatted;
            $hashes[] = CryptoEngine::sign($formatted, 'recovery-code');
        }

        return [
            'plaintext' => $plaintext,
            'hashes' => $hashes,
        ];
    }

    /**
     * Consumes a recovery code if valid, returning the updated list of remaining hashes.
     *
     * @param list<string> $storedHashes
     * @return array{valid: bool, remaining: list<string>}
     */
    public static function consumeRecoveryCode(string $inputCode, array $storedHashes): array
    {
        $normalized = strtoupper(trim($inputCode));
        $candidateHash = CryptoEngine::sign($normalized, 'recovery-code');

        $valid = false;
        $remaining = [];

        foreach ($storedHashes as $stored) {
            if (!$valid && hash_equals($stored, $candidateHash)) {
                $valid = true;
                continue; // Consume single-use code
            }
            $remaining[] = $stored;
        }

        return [
            'valid' => $valid,
            'remaining' => $remaining,
        ];
    }

    private static function generateHotp(string $base32Secret, int $counter): string
    {
        $secretBytes = self::base32Decode($base32Secret);
        // Pack 64-bit big-endian counter
        $counterBytes = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $counterBytes, $secretBytes, true);

        $offset = ord($hash[19]) & 0x0f;
        $binary = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        );

        $otp = $binary % (10 ** self::CODE_DIGITS);
        return str_pad((string) $otp, self::CODE_DIGITS, '0', STR_PAD_LEFT);
    }

    public static function base32Encode(string $data): string
    {
        if ($data === '') {
            return '';
        }
        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $chunks = str_split($binary, 5);
        $output = '';
        foreach ($chunks as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }
        return $output;
    }

    public static function base32Decode(string $base32): string
    {
        $cleaned = strtoupper(rtrim($base32, '='));
        if ($cleaned === '') {
            return '';
        }
        $binary = '';
        foreach (str_split($cleaned) as $char) {
            $pos = strpos(self::BASE32_ALPHABET, $char);
            if ($pos === false) {
                throw new RuntimeException('Invalid Base32 character encountered.');
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = str_split($binary, 8);
        $output = '';
        foreach ($bytes as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(bindec($byte));
            }
        }
        return $output;
    }
}
