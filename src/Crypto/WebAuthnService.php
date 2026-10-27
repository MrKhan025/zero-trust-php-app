<?php

declare(strict_types=1);

namespace ZeroTrust\Crypto;

use RuntimeException;
use ZeroTrust\Core\Config;
use ZeroTrust\Core\Database;
use ZeroTrust\Storage\StorageFactory;

/**
 * Pure-PHP WebAuthn / Passkeys implementation (no external libraries).
 * Supports platform authenticators, ES256 (P-256), challenge replay protection,
 * and AEAD-encrypted credential storage.
 */
final class WebAuthnService
{
    private const CHALLENGE_TTL = 300;

    public static function generateRegistrationOptions(string $userUuid, string $username): array
    {
        $challenge = random_bytes(32);
        $challengeB64 = self::base64urlEncode($challenge);

        StorageFactory::get()->set('webauthn:reg:' . $userUuid, $challengeB64, self::CHALLENGE_TTL);

        $rpId = self::getRpId();
        $rpName = Config::get('APP_NAME', 'ZeroTrust Shield') ?? 'ZeroTrust Shield';

        return [
            'challenge' => $challengeB64,
            'rp' => ['name' => $rpName, 'id' => $rpId],
            'user' => [
                'id' => self::base64urlEncode($userUuid),
                'name' => $username,
                'displayName' => $username,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'residentKey' => 'preferred',
                'userVerification' => 'preferred',
            ],
            'timeout' => 60000,
            'attestation' => 'none',
        ];
    }

    public static function verifyAndStoreRegistration(
        string $userUuid,
        array $clientDataJSON,
        string $attestationObjectB64,
        string $credentialIdB64
    ): array {
        $storage = StorageFactory::get();
        $expectedChallengeB64 = $storage->get('webauthn:reg:' . $userUuid);

        if ($expectedChallengeB64 === null) {
            return ['success' => false, 'message' => 'Registration challenge expired or missing.'];
        }

        $clientData = self::parseClientData($clientDataJSON);
        if ($clientData === null || ($clientData['type'] ?? '') !== 'webauthn.create') {
            return ['success' => false, 'message' => 'Invalid clientDataJSON.'];
        }

        if (!hash_equals($expectedChallengeB64, $clientData['challenge'] ?? '')) {
            return ['success' => false, 'message' => 'Challenge mismatch.'];
        }

        if (!self::isValidOrigin($clientData['origin'] ?? '')) {
            return ['success' => false, 'message' => 'Invalid origin.'];
        }

        $attestationObject = self::base64urlDecode($attestationObjectB64);
        if ($attestationObject === null) {
            return ['success' => false, 'message' => 'Invalid attestationObject.'];
        }

        $authData = self::extractAuthDataFromAttestation($attestationObject);
        if ($authData === null) {
            return ['success' => false, 'message' => 'Could not parse authenticator data.'];
        }

        $rpIdHash = hash('sha256', self::getRpId(), true);
        if (!hash_equals($rpIdHash, substr($authData, 0, 32))) {
            return ['success' => false, 'message' => 'rpIdHash mismatch.'];
        }

        $publicKeyPem = self::extractPublicKeyPem($authData);
        if ($publicKeyPem === null) {
            return ['success' => false, 'message' => 'Could not extract public key (COSE parse failed).'];
        }

        $credential = [
            'id' => $credentialIdB64,
            'publicKey' => $publicKeyPem,
            'signCount' => self::extractSignCount($authData),
            'created_at' => time(),
        ];

        self::storeCredential($userUuid, $credential);
        $storage->delete('webauthn:reg:' . $userUuid);

        return [
            'success' => true,
            'message' => 'Passkey registered successfully.',
            'credential_id' => $credentialIdB64,
        ];
    }

    public static function generateAuthenticationOptions(string $userUuid): array
    {
        $challenge = random_bytes(32);
        $challengeB64 = self::base64urlEncode($challenge);
        StorageFactory::get()->set('webauthn:auth:' . $userUuid, $challengeB64, self::CHALLENGE_TTL);

        $credentials = self::loadCredentials($userUuid);
        $allowCredentials = [];
        foreach ($credentials as $cred) {
            $allowCredentials[] = ['type' => 'public-key', 'id' => $cred['id']];
        }

        return [
            'challenge' => $challengeB64,
            'timeout' => 60000,
            'rpId' => self::getRpId(),
            'allowCredentials' => $allowCredentials,
            'userVerification' => 'preferred',
        ];
    }

    public static function verifyAssertion(
        string $userUuid,
        string $credentialIdB64,
        array $clientDataJSON,
        string $authenticatorDataB64,
        string $signatureB64
    ): array {
        $storage = StorageFactory::get();
        $expectedChallengeB64 = $storage->get('webauthn:auth:' . $userUuid);

        if ($expectedChallengeB64 === null) {
            return ['success' => false, 'message' => 'Authentication challenge expired or missing.'];
        }

        $credentials = self::loadCredentials($userUuid);
        $credential = null;
        foreach ($credentials as $c) {
            if (hash_equals($c['id'], $credentialIdB64)) {
                $credential = $c;
                break;
            }
        }

        if ($credential === null) {
            return ['success' => false, 'message' => 'Unknown credential.'];
        }

        $clientData = self::parseClientData($clientDataJSON);
        if ($clientData === null || ($clientData['type'] ?? '') !== 'webauthn.get') {
            return ['success' => false, 'message' => 'Invalid clientDataJSON.'];
        }

        if (!hash_equals($expectedChallengeB64, $clientData['challenge'] ?? '')) {
            return ['success' => false, 'message' => 'Challenge mismatch.'];
        }

        if (!self::isValidOrigin($clientData['origin'] ?? '')) {
            return ['success' => false, 'message' => 'Invalid origin.'];
        }

        $authData = self::base64urlDecode($authenticatorDataB64);
        if ($authData === null || strlen($authData) < 37) {
            return ['success' => false, 'message' => 'Invalid authenticatorData.'];
        }

        $rpIdHash = hash('sha256', self::getRpId(), true);
        if (!hash_equals($rpIdHash, substr($authData, 0, 32))) {
            return ['success' => false, 'message' => 'rpIdHash mismatch.'];
        }

        $flags = ord($authData[32]);
        if (($flags & 0x01) === 0) {
            return ['success' => false, 'message' => 'User presence flag not set.'];
        }

        $clientDataHash = hash('sha256', json_encode($clientDataJSON, JSON_UNESCAPED_SLASHES), true);
        $signedData = $authData . $clientDataHash;
        $signature = self::base64urlDecode($signatureB64);

        if ($signature === null) {
            return ['success' => false, 'message' => 'Invalid signature encoding.'];
        }

        $publicKey = openssl_pkey_get_public($credential['publicKey']);
        if ($publicKey === false) {
            return ['success' => false, 'message' => 'Invalid stored public key.'];
        }

        $verified = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            return ['success' => false, 'message' => 'Signature verification failed.'];
        }

        $newSignCount = self::extractSignCount($authData);
        if ($newSignCount > 0 && $newSignCount <= ($credential['signCount'] ?? 0)) {
            return ['success' => false, 'message' => 'Sign count regression detected.'];
        }

        $credential['signCount'] = $newSignCount;
        self::updateCredential($userUuid, $credential);
        $storage->delete('webauthn:auth:' . $userUuid);

        return ['success' => true, 'message' => 'Passkey authentication successful.'];
    }

    // --------------- helpers ---------------

    private static function getRpId(): string
    {
        $url = Config::get('APP_URL', 'http://localhost') ?? 'http://localhost';
        $host = parse_url($url, PHP_URL_HOST);
        return is_string($host) && $host !== '' ? $host : 'localhost';
    }

    private static function isValidOrigin(string $origin): bool
    {
        $expected = rtrim(Config::get('APP_URL', 'http://localhost') ?? 'http://localhost', '/');
        return hash_equals($expected, rtrim($origin, '/'));
    }

    private static function parseClientData(array|string $clientDataJSON): ?array
    {
        if (is_string($clientDataJSON)) {
            $decoded = json_decode($clientDataJSON, true);
            return is_array($decoded) ? $decoded : null;
        }
        return $clientDataJSON;
    }

    private static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64urlDecode(string $data): ?string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private static function extractAuthDataFromAttestation(string $attestationObject): ?string
    {
        try {
            $offset = 0;
            $map = self::cborDecode($attestationObject, $offset);
            if (!is_array($map) || !isset($map['authData']) || !is_string($map['authData'])) {
                return null;
            }
            return $map['authData'];
        } catch (\Throwable) {
            return null;
        }
    }

    private static function extractSignCount(string $authData): int
    {
        if (strlen($authData) < 37) return 0;
        $count = unpack('N', substr($authData, 33, 4));
        return (int) ($count[1] ?? 0);
    }

    private static function extractPublicKeyPem(string $authData): ?string
    {
        if (strlen($authData) < 37) return null;
        $offset = 37;
        $flags = ord($authData[32]);
        if (($flags & 0x40) === 0) return null;

        $offset += 16; // AAGUID
        if ($offset + 2 > strlen($authData)) return null;
        $credIdLen = unpack('n', substr($authData, $offset, 2))[1];
        $offset += 2 + $credIdLen;

        $coseRaw = substr($authData, $offset);
        if ($coseRaw === '') return null;

        try {
            $coseOffset = 0;
            $coseKey = self::cborDecode($coseRaw, $coseOffset);
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($coseKey)) return null;

        $kty = $coseKey[1] ?? null;
        if ($kty === 2) { // EC2
            $crv = $coseKey[-1] ?? null;
            $x = $coseKey[-2] ?? null;
            $y = $coseKey[-3] ?? null;
            if ($crv === 1 && is_string($x) && is_string($y) && strlen($x) === 32 && strlen($y) === 32) {
                return self::ecPublicKeyToPem($x, $y);
            }
        }
        return null;
    }

    private static function ecPublicKeyToPem(string $x, string $y): string
    {
        $point = "\x04" . $x . $y;
        $oidEcPublicKey = hex2bin('06072a8648ce3d0201');
        $oidPrime256v1  = hex2bin('06082a8648ce3d030107');
        $algorithm = self::asn1Sequence($oidEcPublicKey . $oidPrime256v1);
        $bitString = "\x03" . self::asn1Length(strlen($point) + 1) . "\x00" . $point;
        $spki = self::asn1Sequence($algorithm . $bitString);
        return "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split(base64_encode($spki), 64, "\n") .
               "-----END PUBLIC KEY-----";
    }

    private static function asn1Length(int $length): string
    {
        if ($length < 0x80) return chr($length);
        if ($length < 0x100) return "\x81" . chr($length);
        return "\x82" . pack('n', $length);
    }

    private static function asn1Sequence(string $contents): string
    {
        return "\x30" . self::asn1Length(strlen($contents)) . $contents;
    }

    // Minimal CBOR decoder
    private static function cborDecode(string $data, int &$offset = 0): mixed
    {
        if ($offset >= strlen($data)) throw new RuntimeException('CBOR: unexpected end');
        $header = ord($data[$offset++]);
        $major = $header >> 5;
        $info  = $header & 0x1F;
        $value = self::cborReadLength($data, $offset, $info);

        return match ($major) {
            0 => $value,
            1 => -1 - $value,
            2, 3 => self::cborReadBytes($data, $offset, $value),
            4 => self::cborReadArray($data, $offset, $value),
            5 => self::cborReadMap($data, $offset, $value),
            7 => match ($info) { 20 => false, 21 => true, 22, 23 => null, default => $value },
            default => throw new RuntimeException("CBOR unsupported major $major"),
        };
    }

    private static function cborReadLength(string $data, int &$offset, int $info): int
    {
        if ($info < 24) return $info;
        if ($info === 24) return ord($data[$offset++]);
        if ($info === 25) { $v = unpack('n', substr($data, $offset, 2))[1]; $offset += 2; return $v; }
        if ($info === 26) { $v = unpack('N', substr($data, $offset, 4))[1]; $offset += 4; return $v; }
        throw new RuntimeException('CBOR length too large');
    }

    private static function cborReadBytes(string $data, int &$offset, int $length): string
    {
        $bytes = substr($data, $offset, $length);
        $offset += $length;
        return $bytes;
    }

    private static function cborReadArray(string $data, int &$offset, int $count): array
    {
        $arr = [];
        for ($i = 0; $i < $count; $i++) $arr[] = self::cborDecode($data, $offset);
        return $arr;
    }

    private static function cborReadMap(string $data, int &$offset, int $count): array
    {
        $map = [];
        for ($i = 0; $i < $count; $i++) {
            $k = self::cborDecode($data, $offset);
            $v = self::cborDecode($data, $offset);
            $map[$k] = $v;
        }
        return $map;
    }

    private static function storeCredential(string $userUuid, array $credential): void
    {
        $existing = self::loadCredentials($userUuid);
        $existing[] = $credential;
        self::saveCredentials($userUuid, $existing);
    }

    private static function updateCredential(string $userUuid, array $updated): void
    {
        $existing = self::loadCredentials($userUuid);
        foreach ($existing as &$cred) {
            if (hash_equals($cred['id'], $updated['id'])) {
                $cred = $updated;
                break;
            }
        }
        self::saveCredentials($userUuid, $existing);
    }

    private static function loadCredentials(string $userUuid): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT webauthn_credentials_encrypted FROM users WHERE uuid = :uuid LIMIT 1');
        $stmt->execute([':uuid' => $userUuid]);
        $row = $stmt->fetch();
        if ($row === false || empty($row['webauthn_credentials_encrypted'])) return [];

        try {
            $json = CryptoEngine::decrypt(
                (string) $row['webauthn_credentials_encrypted'],
                $userUuid . '|webauthn',
                'user-mfa'
            );
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            return is_array($data) ? $data : [];
        } catch (\Throwable) {
            return [];
        }
    }

    private static function saveCredentials(string $userUuid, array $credentials): void
    {
        $pdo = Database::connection();
        $json = json_encode($credentials, JSON_THROW_ON_ERROR);
        $encrypted = CryptoEngine::encrypt($json, $userUuid . '|webauthn', 'user-mfa');
        $stmt = $pdo->prepare('UPDATE users SET webauthn_credentials_encrypted = :cred WHERE uuid = :uuid');
        $stmt->execute([':cred' => $encrypted, ':uuid' => $userUuid]);
    }
}
