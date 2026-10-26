<?php

declare(strict_types=1);

namespace ZeroTrust\Auth;

use PDO;
use RuntimeException;
use ZeroTrust\Audit\AuditLedger;
use ZeroTrust\Core\Config;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;
use ZeroTrust\Crypto\TotpAuthenticator;
use ZeroTrust\Defense\BotDefenseGuard;
use ZeroTrust\Defense\RateLimiter;
use ZeroTrust\Policy\ZeroTrustPolicyEngine;

/**
 * Core Zero-Trust Identity, Authentication, MFA & Session Lifecycle Service.
 *
 * Implements:
 * - Strong password policy enforcement + Argon2id with HMAC-SHA256 peppering
 * - Blind-indexed + AEAD-encrypted PII storage (email & TOTP secrets encrypted at rest)
 * - Timing-equalized authentication against username enumeration
 * - Proof-of-Work verification on all unauthenticated state transitions
 * - Continuous session token rotation and device/network binding
 */
final class ZeroTrustAuthService
{
    /**
     * Registers a new identity with encrypted PII, Argon2id-peppered password,
     * pre-provisioned TOTP secret, and single-use recovery codes.
     *
     * @param array<string, mixed> $payload
     * @return array{success: bool, message: string, user_uuid?: string, totp_secret?: string, totp_uri?: string, recovery_codes?: list<string>}
     */
    public static function registerUser(
        array $payload,
        string $clientIp,
        bool $requirePow = true
    ): array {
        // 1. Check Rate Limit
        $rate = RateLimiter::check('register', $clientIp);
        if (!$rate['allowed']) {
            AuditLedger::record('REGISTER_RATE_LIMITED', 'WARNING', $clientIp, null, 60, [
                'retry_after' => $rate['retry_after'],
            ]);
            return ['success' => false, 'message' => 'Too many registration attempts. Please try again later.'];
        }

        // 2. Verify Anti-AI Proof-of-Work Challenge
        if ($requirePow) {
            $pow = BotDefenseGuard::verifySubmission($payload, $clientIp);
            if (!$pow['passed']) {
                RateLimiter::hit('register', $clientIp);
                AuditLedger::record('REGISTER_BOT_DEFENSE_BLOCKED', 'HIGH', $clientIp, null, 85, [
                    'reason' => $pow['reason'],
                ]);
                return ['success' => false, 'message' => 'Cryptographic Proof-of-Work verification failed (' . $pow['reason'] . ').'];
            }
        }

        $username = trim((string) ($payload['username'] ?? ''));
        $email = strtolower(trim((string) ($payload['email'] ?? '')));
        $password = (string) ($payload['password'] ?? '');

        // 3. Validate Username & Email format
        if (preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $username) !== 1) {
            return ['success' => false, 'message' => 'Username must be 3-32 alphanumeric characters.'];
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return ['success' => false, 'message' => 'Invalid email address format.'];
        }

        // 4. Enforce High-Entropy Password Policy (NIST SP 800-63B + Complexity Guard)
        $passwordCheck = self::validatePasswordStrength($password, $username, $email);
        if (!$passwordCheck['valid']) {
            return ['success' => false, 'message' => $passwordCheck['reason']];
        }

        $pdo = Database::connection();
        $emailHash = CryptoEngine::blindIndex($email, 'email');

        // 5. Check for existing username or blind-indexed email
        $check = $pdo->prepare('SELECT id FROM users WHERE username = :username OR email_hash = :email_hash LIMIT 1');
        $check->execute([':username' => $username, ':email_hash' => $emailHash]);
        if ($check->fetch() !== false) {
            RateLimiter::hit('register', $clientIp);
            AuditLedger::record('REGISTER_CONFLICT', 'INFO', $clientIp, null, 20, ['username' => $username]);
            return ['success' => false, 'message' => 'Account could not be registered with the provided credentials.'];
        }

        // 6. Encrypt PII & Generate MFA Credentials
        $userUuid = CryptoEngine::uuidV4();
        $emailEncrypted = CryptoEngine::encrypt($email, $userUuid . '|email', 'user-pii');
        $passwordHash = CryptoEngine::hashPassword($password);

        $totpSecret = TotpAuthenticator::generateSecret();
        $totpEncrypted = CryptoEngine::encrypt($totpSecret, $userUuid . '|totp', 'user-mfa');
        $recovery = TotpAuthenticator::generateRecoveryCodes(8);
        $recoveryJsonEncrypted = CryptoEngine::encrypt(
            json_encode($recovery['hashes'], JSON_THROW_ON_ERROR),
            $userUuid . '|recovery',
            'user-mfa'
        );

        $now = time();
        $insert = $pdo->prepare('
            INSERT INTO users (
                uuid, email_hash, email_encrypted, username, password_hash,
                role, mfa_enabled, totp_secret_encrypted, recovery_codes_json,
                account_locked_until, failed_attempts, created_at
            ) VALUES (
                :uuid, :email_hash, :email_encrypted, :username, :password_hash,
                :role, 1, :totp_encrypted, :recovery_json,
                0, 0, :created_at
            )
        ');

        $insert->execute([
            ':uuid' => $userUuid,
            ':email_hash' => $emailHash,
            ':email_encrypted' => $emailEncrypted,
            ':username' => $username,
            ':password_hash' => $passwordHash,
            ':role' => 'security_admin',
            ':totp_encrypted' => $totpEncrypted,
            ':recovery_json' => $recoveryJsonEncrypted,
            ':created_at' => $now,
        ]);

        $userId = (int) $pdo->lastInsertId();
        AuditLedger::record('IDENTITY_PROVISIONED', 'INFO', $clientIp, $userId, 0, [
            'username' => $username,
            'uuid' => $userUuid,
            'mfa_enabled' => true,
        ]);

        return [
            'success' => true,
            'message' => 'Zero-Trust identity provisioned with AEAD encryption and RFC 6238 TOTP.',
            'user_uuid' => $userUuid,
            'totp_secret' => $totpSecret,
            'totp_uri' => TotpAuthenticator::getProvisioningUri($username, $totpSecret),
            'recovery_codes' => $recovery['plaintext'],
        ];
    }

    /**
     * Authenticates primary credentials + Proof-of-Work + TOTP / Recovery Code and issues
     * a cryptographically bound Zero-Trust session token.
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $server
     * @return array{success: bool, status: string, message: string, session_token?: string, session_id?: string, user?: array<string, mixed>}
     */
    public static function authenticate(
        array $payload,
        string $clientIp,
        array $server,
        bool $requirePow = true
    ): array {
        $identifier = trim((string) ($payload['username'] ?? ''));
        $password = (string) ($payload['password'] ?? '');
        $totpCode = trim((string) ($payload['totp_code'] ?? ''));
        $recoveryCode = trim((string) ($payload['recovery_code'] ?? ''));

        // 1. Check IP & Account Rate Limit
        $ipLimit = RateLimiter::check('login_ip', $clientIp);
        $acctLimit = RateLimiter::check('login_acct', strtolower($identifier));
        if (!$ipLimit['allowed'] || !$acctLimit['allowed']) {
            AuditLedger::record('AUTH_RATE_LIMITED', 'WARNING', $clientIp, null, 70, [
                'identifier' => $identifier,
            ]);
            return [
                'success' => false,
                'status' => 'RATE_LIMITED',
                'message' => 'Authentication temporarily locked due to rate limit policy.',
            ];
        }

        // 2. Verify Anti-AI Proof-of-Work Challenge
        if ($requirePow) {
            $pow = BotDefenseGuard::verifySubmission($payload, $clientIp);
            if (!$pow['passed']) {
                RateLimiter::hit('login_ip', $clientIp);
                AuditLedger::record('AUTH_POW_FAILED', 'HIGH', $clientIp, null, 85, [
                    'reason' => $pow['reason'],
                ]);
                return [
                    'success' => false,
                    'status' => 'POW_FAILED',
                    'message' => 'Proof-of-Work anti-automation verification failed (' . $pow['reason'] . ').',
                ];
            }
        }

        $pdo = Database::connection();
        $emailHash = CryptoEngine::blindIndex($identifier, 'email');

        $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username OR email_hash = :email_hash LIMIT 1');
        $stmt->execute([':username' => $identifier, ':email_hash' => $emailHash]);
        $user = $stmt->fetch();

        // 3. Equalize timing if user does not exist
        if ($user === false) {
            CryptoEngine::mitigateTimingEnumeration($password);
            RateLimiter::hit('login_ip', $clientIp);
            RateLimiter::hit('login_acct', strtolower($identifier));
            AuditLedger::record('AUTH_UNKNOWN_IDENTITY', 'WARNING', $clientIp, null, 45, [
                'identifier_hash' => CryptoEngine::blindIndex($identifier, 'audit-id'),
            ]);
            return [
                'success' => false,
                'status' => 'INVALID_CREDENTIALS',
                'message' => 'Invalid credentials or multi-factor authentication code.',
            ];
        }

        $userId = (int) $user['id'];
        $userUuid = (string) $user['uuid'];
        $now = time();

        // 4. Check Account Lockout Window
        if ((int) $user['account_locked_until'] > $now) {
            AuditLedger::record('AUTH_LOCKED_ACCOUNT_ATTEMPT', 'WARNING', $clientIp, $userId, 75, [
                'locked_until' => (int) $user['account_locked_until'],
            ]);
            return [
                'success' => false,
                'status' => 'ACCOUNT_LOCKED',
                'message' => 'Account is temporarily locked due to repeated failed authentication attempts.',
            ];
        }

        // 5. Verify Password (Argon2id + HMAC-SHA256 Pepper)
        if (!CryptoEngine::verifyPassword($password, (string) $user['password_hash'])) {
            self::recordFailedUserLogin($userId, (int) $user['failed_attempts'], $clientIp);
            return [
                'success' => false,
                'status' => 'INVALID_CREDENTIALS',
                'message' => 'Invalid credentials or multi-factor authentication code.',
            ];
        }

        // 6. Verify Multi-Factor Authentication (RFC 6238 TOTP or Single-Use Recovery Code)
        $mfaVerified = false;
        if ((int) $user['mfa_enabled'] === 1 && $user['totp_secret_encrypted'] !== null) {
            $totpSecret = CryptoEngine::decrypt(
                (string) $user['totp_secret_encrypted'],
                $userUuid . '|totp',
                'user-mfa'
            );

            if ($totpCode !== '') {
                $timeSlice = (int) floor($now / 30);
                if (TotpAuthenticator::verifyCode($totpSecret, $totpCode, 1, $now)) {
                    // Prevent TOTP replay within the same 30s window
                    $replayKey = $userUuid . ':totp:' . $timeSlice . ':' . $totpCode;
                    if (!BotDefenseGuard::consumeNonce($replayKey, 'totp', $now + 90)) {
                        CryptoEngine::wipe($totpSecret);
                        AuditLedger::record('AUTH_TOTP_REPLAY_BLOCKED', 'CRITICAL', $clientIp, $userId, 95, []);
                        return [
                            'success' => false,
                            'status' => 'TOTP_REPLAYED',
                            'message' => 'This TOTP code was already consumed. Wait for the next 30-second window.',
                        ];
                    }
                    $mfaVerified = true;
                }
            } elseif ($recoveryCode !== '' && $user['recovery_codes_json'] !== null) {
                $decryptedRecoveryJson = CryptoEngine::decrypt(
                    (string) $user['recovery_codes_json'],
                    $userUuid . '|recovery',
                    'user-mfa'
                );
                /** @var list<string> $storedHashes */
                $storedHashes = json_decode($decryptedRecoveryJson, true, 512, JSON_THROW_ON_ERROR);
                $consumed = TotpAuthenticator::consumeRecoveryCode($recoveryCode, $storedHashes);
                if ($consumed['valid']) {
                    $mfaVerified = true;
                    $newEncryptedRecovery = CryptoEngine::encrypt(
                        json_encode($consumed['remaining'], JSON_THROW_ON_ERROR),
                        $userUuid . '|recovery',
                        'user-mfa'
                    );
                    $upd = $pdo->prepare('UPDATE users SET recovery_codes_json = :rc WHERE id = :id');
                    $upd->execute([':rc' => $newEncryptedRecovery, ':id' => $userId]);
                    AuditLedger::record('AUTH_RECOVERY_CODE_CONSUMED', 'WARNING', $clientIp, $userId, 30, [
                        'remaining_codes' => count($consumed['remaining']),
                    ]);
                }
            }

            CryptoEngine::wipe($totpSecret);

            if (!$mfaVerified) {
                self::recordFailedUserLogin($userId, (int) $user['failed_attempts'], $clientIp);
                return [
                    'success' => false,
                    'status' => 'MFA_REQUIRED_OR_INVALID',
                    'message' => 'Invalid credentials or multi-factor authentication code.',
                ];
            }
        }

        // 7. Reset failed attempts & issue Zero-Trust Session bound to Device + IP Subnet
        RateLimiter::clear('login_ip', $clientIp);
        RateLimiter::clear('login_acct', strtolower($identifier));

        $reset = $pdo->prepare('UPDATE users SET failed_attempts = 0, account_locked_until = 0, last_login_at = :now WHERE id = :id');
        $reset->execute([':now' => $now, ':id' => $userId]);

        $session = self::issueSession($userId, $clientIp, $server, $mfaVerified);

        $decryptedEmail = CryptoEngine::decrypt((string) $user['email_encrypted'], $userUuid . '|email', 'user-pii');

        AuditLedger::record('AUTH_SESSION_ISSUED', 'INFO', $clientIp, $userId, 0, [
            'session_id' => $session['session_id'],
            'mfa_verified' => $mfaVerified,
        ]);

        return [
            'success' => true,
            'status' => 'AUTHENTICATED',
            'message' => 'Zero-Trust session established and cryptographically bound.',
            'session_token' => $session['raw_token'],
            'session_id' => $session['session_id'],
            'user' => [
                'id' => $userId,
                'uuid' => $userUuid,
                'username' => (string) $user['username'],
                'email' => $decryptedEmail,
                'role' => (string) $user['role'],
                'mfa_verified' => $mfaVerified,
            ],
        ];
    }

    /**
     * Continuously validates an active session token against the Zero-Trust Policy Engine.
     * Rotates the underlying token automatically when rotation interval elapses.
     *
     * @param array<string, mixed> $server
     * @return array{authenticated: bool, decision: string, risk_score: int, signals: list<string>, rotated_token?: string, user?: array<string, mixed>, session?: array<string, mixed>}
     */
    public static function verifyAndEvaluateSession(
        string $rawToken,
        string $clientIp,
        array $server,
        bool $requiresHighAssurance = false
    ): array {
        if ($rawToken === '' || strlen($rawToken) < 32) {
            return [
                'authenticated' => false,
                'decision' => ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE,
                'risk_score' => 100,
                'signals' => ['MISSING_OR_MALFORMED_TOKEN'],
            ];
        }

        $pdo = Database::connection();
        $tokenHash = CryptoEngine::blindIndex($rawToken, 'session-token');

        $stmt = $pdo->prepare('
            SELECT s.*, u.uuid AS user_uuid, u.username, u.email_encrypted, u.role
            FROM zt_sessions s
            INNER JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = :token_hash
            LIMIT 1
        ');
        $stmt->execute([':token_hash' => $tokenHash]);
        $row = $stmt->fetch();

        if ($row === false) {
            AuditLedger::record('SESSION_INVALID_TOKEN_PRESENTED', 'WARNING', $clientIp, null, 80, []);
            return [
                'authenticated' => false,
                'decision' => ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE,
                'risk_score' => 100,
                'signals' => ['UNKNOWN_SESSION_TOKEN'],
            ];
        }

        $sessionId = (string) $row['session_id'];
        $userId = (int) $row['user_id'];
        $evaluation = ZeroTrustPolicyEngine::evaluateSession($row, $clientIp, $server, $requiresHighAssurance);

        if ($evaluation['decision'] === ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE) {
            $revoke = $pdo->prepare('UPDATE zt_sessions SET revoked = 1, risk_score = :risk WHERE session_id = :sid');
            $revoke->execute([':risk' => $evaluation['risk_score'], ':sid' => $sessionId]);

            AuditLedger::record('SESSION_TERMINATED_BY_ZERO_TRUST_POLICY', 'CRITICAL', $clientIp, $userId, $evaluation['risk_score'], [
                'session_id' => $sessionId,
                'signals' => $evaluation['signals'],
            ]);

            return [
                'authenticated' => false,
                'decision' => $evaluation['decision'],
                'risk_score' => $evaluation['risk_score'],
                'signals' => $evaluation['signals'],
            ];
        }

        $now = time();
        $rotatedToken = null;

        if ($evaluation['rotate_token']) {
            $rotatedToken = bin2hex(random_bytes(32));
            $newTokenHash = CryptoEngine::blindIndex($rotatedToken, 'session-token');
            $upd = $pdo->prepare('
                UPDATE zt_sessions
                SET token_hash = :th, last_rotated_at = :now, last_active_at = :now, risk_score = :risk
                WHERE session_id = :sid
            ');
            $upd->execute([
                ':th' => $newTokenHash,
                ':now' => $now,
                ':risk' => $evaluation['risk_score'],
                ':sid' => $sessionId,
            ]);
        } else {
            $upd = $pdo->prepare('
                UPDATE zt_sessions
                SET last_active_at = :now, risk_score = :risk
                WHERE session_id = :sid
            ');
            $upd->execute([
                ':now' => $now,
                ':risk' => $evaluation['risk_score'],
                ':sid' => $sessionId,
            ]);
        }

        if ($evaluation['decision'] === ZeroTrustPolicyEngine::DECISION_STEP_UP_MFA) {
            AuditLedger::record('SESSION_STEP_UP_MFA_TRIGGERED', 'WARNING', $clientIp, $userId, $evaluation['risk_score'], [
                'session_id' => $sessionId,
                'signals' => $evaluation['signals'],
            ]);
        }

        $userUuid = (string) $row['user_uuid'];
        $decryptedEmail = CryptoEngine::decrypt((string) $row['email_encrypted'], $userUuid . '|email', 'user-pii');

        $result = [
            'authenticated' => true,
            'decision' => $evaluation['decision'],
            'risk_score' => $evaluation['risk_score'],
            'signals' => $evaluation['signals'],
            'user' => [
                'id' => $userId,
                'uuid' => $userUuid,
                'username' => (string) $row['username'],
                'email' => $decryptedEmail,
                'role' => (string) $row['role'],
            ],
            'session' => [
                'session_id' => $sessionId,
                'mfa_verified' => (int) $row['mfa_verified'] === 1,
                'issued_at' => (int) $row['issued_at'],
                'last_rotated_at' => $evaluation['rotate_token'] ? $now : (int) $row['last_rotated_at'],
                'expires_at' => (int) $row['expires_at'],
            ],
        ];

        if ($rotatedToken !== null) {
            $result['rotated_token'] = $rotatedToken;
        }

        return $result;
    }

    /**
     * Revokes a session immediately.
     */
    public static function revokeSession(string $rawToken, string $clientIp): void
    {
        if ($rawToken === '') {
            return;
        }
        $pdo = Database::connection();
        $tokenHash = CryptoEngine::blindIndex($rawToken, 'session-token');
        $stmt = $pdo->prepare('UPDATE zt_sessions SET revoked = 1 WHERE token_hash = :th');
        $stmt->execute([':th' => $tokenHash]);

        AuditLedger::record('SESSION_EXPLICIT_LOGOUT', 'INFO', $clientIp, null, 0, []);
    }

    /**
     * Generates a synchronizer + HMAC-bound CSRF token tied to the active session ID.
     */
    public static function generateCsrfToken(string $sessionId): string
    {
        $timestamp = (string) time();
        $mac = CryptoEngine::sign($sessionId . '|' . $timestamp, 'csrf-token');
        return base64_encode($timestamp . '|' . $mac);
    }

    /**
     * Verifies a session-bound CSRF token within a 2-hour validity window.
     */
    public static function verifyCsrfToken(string $sessionId, string $csrfToken): bool
    {
        $decoded = base64_decode($csrfToken, true);
        if ($decoded === false) {
            return false;
        }
        $parts = explode('|', $decoded, 2);
        if (count($parts) !== 2) {
            return false;
        }
        $timestamp = (int) $parts[0];
        $mac = $parts[1];

        if ((time() - $timestamp) > 7200) {
            return false;
        }

        return CryptoEngine::verifySignature($sessionId . '|' . $parts[0], $mac, 'csrf-token');
    }

    /**
     * @param array<string, mixed> $server
     * @return array{session_id: string, raw_token: string}
     */
    private static function issueSession(int $userId, string $clientIp, array $server, bool $mfaVerified): array
    {
        $pdo = Database::connection();
        $sessionId = CryptoEngine::uuidV4();
        $rawToken = bin2hex(random_bytes(32));
        $tokenHash = CryptoEngine::blindIndex($rawToken, 'session-token');

        $deviceFp = ZeroTrustPolicyEngine::computeDeviceFingerprint($server);
        $ipSubnetHash = ZeroTrustPolicyEngine::computeIpSubnetHash($clientIp);
        $uaHash = ZeroTrustPolicyEngine::computeUserAgentHash((string) ($server['HTTP_USER_AGENT'] ?? ''));

        $now = time();
        $lifetime = Config::getInt('ZT_SESSION_ABSOLUTE_LIFETIME', 14400);

        $insert = $pdo->prepare('
            INSERT INTO zt_sessions (
                session_id, user_id, token_hash, device_fingerprint_hash,
                ip_subnet_hash, user_agent_hash, mfa_verified, risk_score,
                issued_at, last_rotated_at, last_active_at, expires_at, revoked
            ) VALUES (
                :sid, :uid, :th, :dfp,
                :iph, :uah, :mfa, 0,
                :now, :now, :now, :exp, 0
            )
        ');

        $insert->execute([
            ':sid' => $sessionId,
            ':uid' => $userId,
            ':th' => $tokenHash,
            ':dfp' => $deviceFp,
            ':iph' => $ipSubnetHash,
            ':uah' => $uaHash,
            ':mfa' => $mfaVerified ? 1 : 0,
            ':now' => $now,
            ':exp' => $now + $lifetime,
        ]);

        return [
            'session_id' => $sessionId,
            'raw_token' => $rawToken,
        ];
    }

    private static function recordFailedUserLogin(int $userId, int $currentFailures, string $clientIp): void
    {
        $pdo = Database::connection();
        $newFailures = $currentFailures + 1;
        $maxAttempts = Config::getInt('ZT_RATE_LIMIT_MAX_ATTEMPTS', 5);
        $lockoutSeconds = Config::getInt('ZT_RATE_LIMIT_LOCKOUT_SECONDS', 900);
        $lockedUntil = $newFailures >= $maxAttempts ? (time() + $lockoutSeconds) : 0;

        $upd = $pdo->prepare('UPDATE users SET failed_attempts = :fa, account_locked_until = :lu WHERE id = :id');
        $upd->execute([
            ':fa' => $newFailures,
            ':lu' => $lockedUntil,
            ':id' => $userId,
        ]);

        RateLimiter::hit('login_ip', $clientIp);

        AuditLedger::record('AUTH_FAILED_CREDENTIAL_OR_MFA', 'WARNING', $clientIp, $userId, 65, [
            'failed_attempts' => $newFailures,
            'locked_until' => $lockedUntil,
        ]);
    }

    /**
     * @return array{valid: bool, reason: string}
     */
    public static function validatePasswordStrength(string $password, string $username = '', string $email = ''): array
    {
        if (strlen($password) < 12) {
            return ['valid' => false, 'reason' => 'Password must be at least 12 characters long.'];
        }
        if (strlen($password) > 128) {
            return ['valid' => false, 'reason' => 'Password must not exceed 128 characters.'];
        }
        if (preg_match('/[A-Z]/', $password) !== 1 ||
            preg_match('/[a-z]/', $password) !== 1 ||
            preg_match('/[0-9]/', $password) !== 1 ||
            preg_match('/[^A-Za-z0-9]/', $password) !== 1) {
            return [
                'valid' => false,
                'reason' => 'Password must include uppercase, lowercase, numeric, and special characters.',
            ];
        }
        if ($username !== '' && stripos($password, $username) !== false) {
            return ['valid' => false, 'reason' => 'Password must not contain your username.'];
        }
        $emailLocal = explode('@', $email)[0] ?? '';
        if ($emailLocal !== '' && strlen($emailLocal) >= 3 && stripos($password, $emailLocal) !== false) {
            return ['valid' => false, 'reason' => 'Password must not contain your email identifier.'];
        }
        return ['valid' => true, 'reason' => 'OK'];
    }
}
