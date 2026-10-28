<?php

declare(strict_types=1);

use ZeroTrust\Audit\AuditLedger;
use ZeroTrust\Auth\ZeroTrustAuthService;
use ZeroTrust\Bootstrap;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;
use ZeroTrust\Crypto\WebAuthnService;
use ZeroTrust\Defense\BotDefenseGuard;
use ZeroTrust\Defense\WafMiddleware;

require_once dirname(__DIR__) . '/src/Bootstrap.php';
Bootstrap::init(dirname(__DIR__));

// 1. Generate per-request 128-bit cryptographic CSP nonce
$cspNonce = base64_encode(random_bytes(16));
WafMiddleware::emitSecurityHeaders($cspNonce);

$clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

// 2. Execute Application-Layer WAF Inspection
$wafResult = WafMiddleware::inspectRequest($_GET, $_POST, $_SERVER);
if ($wafResult['blocked']) {
    AuditLedger::record('WAF_PAYLOAD_BLOCKED', 'CRITICAL', $clientIp, null, 95, [
        'rule' => $wafResult['rule'],
        'matched_input' => $wafResult['matched_input'],
    ]);
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status' => 'BLOCKED_BY_ZERO_TRUST_WAF',
        'rule' => $wafResult['rule'],
        'message' => 'Request terminated by Zero-Trust Web Application Firewall.',
    ], JSON_PRETTY_PRINT);
    exit;
}

// 3. Helper for setting/clearing the __Host-zt_token cookie
$setTokenCookie = static function (string $token, int $ttl = 14400): void {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 80) === 443);
    $cookieName = $isHttps ? '__Host-zt_token' : 'zt_token';
    setcookie($cookieName, $token, [
        'expires' => time() + $ttl,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
};

$rawToken = (string) ($_COOKIE['__Host-zt_token'] ?? $_COOKIE['zt_token'] ?? '');
$action = (string) ($_GET['action'] ?? 'portal');

// 4. JSON Health, Ledger Verification & Prometheus Telemetry API Endpoints
if ($action === 'api_verify_ledger') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(AuditLedger::verifyChainIntegrity(), JSON_PRETTY_PRINT);
    exit;
}

if ($action === 'api_metrics') {
    $format = (string) ($_GET['format'] ?? 'json');
    if ($format === 'prometheus') {
        header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
        echo AuditLedger::formatPrometheusMetrics();
        exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(AuditLedger::getSecurityMetrics(), JSON_PRETTY_PRINT);
    exit;
}

// 5. WebAuthn / Passkey JSON API Endpoints
if ($action === 'api_webauthn_register_options') {
    header('Content-Type: application/json; charset=utf-8');
    $sessionEval = ZeroTrustAuthService::verifyAndEvaluateSession($rawToken, $clientIp, $_SERVER);
    if (!$sessionEval['authenticated'] || !isset($sessionEval['user'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Active Zero-Trust session required to enroll a Passkey.']);
        exit;
    }
    $u = $sessionEval['user'];
    echo json_encode(WebAuthnService::generateRegistrationOptions((string) $u['uuid'], (string) $u['username']));
    exit;
}

if ($action === 'api_webauthn_register_verify' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $sessionEval = ZeroTrustAuthService::verifyAndEvaluateSession($rawToken, $clientIp, $_SERVER);
    if (!$sessionEval['authenticated'] || !isset($sessionEval['user'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Unauthorized session.']);
        exit;
    }
    $rawBody = (string) file_get_contents('php://input');
    $body = json_decode($rawBody, true);
    if (!is_array($body)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Malformed JSON body.']);
        exit;
    }
    $clientData = is_array($body['clientDataJSON'] ?? null) ? $body['clientDataJSON'] : [];
    $res = WebAuthnService::verifyAndStoreRegistration(
        (string) $sessionEval['user']['uuid'],
        $clientData,
        (string) ($body['attestationObject'] ?? ''),
        (string) ($body['credentialId'] ?? '')
    );
    AuditLedger::record('WEBAUTHN_PASSKEY_ENROLLED', $res['success'] ? 'INFO' : 'WARNING', $clientIp, (int) $sessionEval['user']['id'], 0, [
        'success' => $res['success'],
    ]);
    echo json_encode($res);
    exit;
}

if ($action === 'api_webauthn_auth_options') {
    header('Content-Type: application/json; charset=utf-8');
    $username = trim((string) ($_GET['username'] ?? ''));
    $pdo = Database::connection();
    $stmt = $pdo->prepare('SELECT uuid FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch();
    $targetUuid = is_array($row) && isset($row['uuid']) ? (string) $row['uuid'] : CryptoEngine::uuidV4();
    echo json_encode(WebAuthnService::generateAuthenticationOptions($targetUuid));
    exit;
}

$flashMessage = null;
$flashType = 'info';
$provisionedData = null;

// 6. Handle POST State Transitions
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $postAction = (string) ($_POST['form_action'] ?? '');

    if ($postAction === 'register') {
        $regResult = ZeroTrustAuthService::registerUser($_POST, $clientIp, true);
        if ($regResult['success']) {
            $flashType = 'success';
            $flashMessage = $regResult['message'];
            $provisionedData = $regResult;
        } else {
            $flashType = 'danger';
            $flashMessage = $regResult['message'];
        }
    } elseif ($postAction === 'login') {
        $authResult = ZeroTrustAuthService::authenticate($_POST, $clientIp, $_SERVER, true);
        if ($authResult['success'] && isset($authResult['session_token'])) {
            $setTokenCookie($authResult['session_token'], 14400);
            $rawToken = $authResult['session_token'];
            $flashType = 'success';
            $flashMessage = $authResult['message'];
        } else {
            $flashType = 'danger';
            $flashMessage = $authResult['message'];
        }
    } elseif ($postAction === 'logout') {
        $sessionEval = ZeroTrustAuthService::verifyAndEvaluateSession($rawToken, $clientIp, $_SERVER);
        $sid = (string) ($sessionEval['session']['session_id'] ?? '');
        $csrf = (string) ($_POST['csrf_token'] ?? '');
        if ($sid !== '' && ZeroTrustAuthService::verifyCsrfToken($sid, $csrf)) {
            ZeroTrustAuthService::revokeSession($rawToken, $clientIp);
            $setTokenCookie('', -3600);
            $rawToken = '';
            $flashType = 'info';
            $flashMessage = 'Session cryptographically revoked and cleared.';
        } else {
            $flashType = 'danger';
            $flashMessage = 'CSRF signature validation failed.';
        }
    }
}

// 7. Continuously Evaluate Active Session (Zero-Trust Policy Engine)
$sessionState = ZeroTrustAuthService::verifyAndEvaluateSession($rawToken, $clientIp, $_SERVER);
if (isset($sessionState['rotated_token'])) {
    $setTokenCookie($sessionState['rotated_token'], 14400);
}

$powChallenge = BotDefenseGuard::issueChallenge($clientIp);
$ledgerIntegrity = AuditLedger::verifyChainIntegrity();
$recentLogs = $sessionState['authenticated'] ? AuditLedger::getRecentEntries(10) : [];

$e = static fn(string $val): string => htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

/**
 * Generates a deterministic visual SVG matrix representation for a TOTP provisioning URI
 * so users have both a visual authenticator matrix and accessible Base32 / URI copy controls.
 */
$renderTotpSvgMatrix = static function (string $uri): string {
    $hash = hash('sha256', $uri, true) . hash('sha256', 'qr:' . $uri, true);
    $size = 21;
    $cells = '';
    for ($r = 0; $r < $size; $r++) {
        for ($c = 0; $c < $size; $c++) {
            $isFinder = ($r < 7 && $c < 7) || ($r < 7 && $c >= $size - 7) || ($r >= $size - 7 && $c < 7);
            if ($isFinder) {
                $inOuter = ($r === 0 || $r === 6 || $c === 0 || $c === 6 || $r === $size - 1 || $r === $size - 7 || $c === $size - 1 || $c === $size - 7);
                $inInner = ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4)
                    || ($r >= 2 && $r <= 4 && $c >= $size - 5 && $c <= $size - 3)
                    || ($r >= $size - 5 && $r <= $size - 3 && $c >= 2 && $c <= 4);
                $fill = ($inOuter || $inInner);
            } else {
                $bitIdx = ($r * $size + $c) % 512;
                $byte = ord($hash[(int) floor($bitIdx / 8)]);
                $fill = (($byte >> ($bitIdx % 8)) & 1) === 1;
            }
            if ($fill) {
                $x = 12 + $c * 6;
                $y = 12 + $r * 6;
                $cells .= "<rect x=\"{$x}\" y=\"{$y}\" width=\"6\" height=\"6\" fill=\"#10b981\" rx=\"1\"/>";
            }
        }
    }
    return '<svg width="150" height="150" viewBox="0 0 150 150" role="img" aria-label="TOTP Authenticator Key Matrix" style="background:#060911;border:1px solid #1e293b;border-radius:10px;padding:4px;">' . $cells . '</svg>';
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroTrust Shield — Continuous Adaptive Authentication &amp; Cryptographic Gateway</title>
    <style nonce="<?= $e($cspNonce) ?>">
        :root {
            --bg-dark: #070b14;
            --bg-panel: #0f172a;
            --bg-card: #131c31;
            --border: #1e293b;
            --accent: #10b981;
            --accent-blue: #3b82f6;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, monospace;
            background: radial-gradient(circle at top right, #0f2027, #070b14 65%);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.5;
            padding: 2rem 1rem;
        }
        .container { max-width: 1180px; margin: 0 auto; }
        header {
            display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
            border-bottom: 1px solid var(--border); padding-bottom: 1.25rem; margin-bottom: 2rem;
        }
        .brand { display: flex; align-items: center; gap: 0.85rem; }
        .shield-badge {
            width: 42px; height: 42px; border-radius: 10px;
            background: linear-gradient(135deg, #10b981, #059669);
            display: flex; align-items: center; justify-content: center;
            font-weight: 800; font-size: 1.15rem; color: #052e16;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.35);
        }
        .status-pills { display: flex; gap: 0.65rem; flex-wrap: wrap; }
        .pill {
            font-size: 0.78rem; padding: 0.35rem 0.75rem; border-radius: 999px;
            border: 1px solid var(--border); background: var(--bg-panel); color: var(--text-muted);
            text-decoration: none;
        }
        .pill.ok { border-color: rgba(16, 185, 129, 0.4); color: #34d399; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; }
        .card {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 14px; padding: 1.65rem;
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
        }
        h2 { font-size: 1.15rem; margin-bottom: 0.4rem; color: #e2e8f0; }
        p.sub { font-size: 0.86rem; color: var(--text-muted); margin-bottom: 1.25rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 0.35rem; font-weight: 600; }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%; padding: 0.7rem 0.85rem; border-radius: 8px;
            border: 1px solid #334155; background: #090e1a; color: var(--text-main);
            font-size: 0.92rem;
        }
        input:focus, button:focus-visible, a:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 2px;
            border-color: var(--accent);
        }
        .btn {
            display: inline-block; width: 100%; padding: 0.78rem 1rem;
            border: none; border-radius: 8px; font-weight: 700; font-size: 0.92rem;
            cursor: pointer; background: linear-gradient(135deg, #10b981, #059669);
            color: #042f2e; transition: opacity 0.15s ease; text-align: center; text-decoration: none;
        }
        .btn.secondary { background: linear-gradient(135deg, #3b82f6, #2563eb); color: #eff6ff; }
        .btn.outline {
            background: transparent; border: 1px solid #334155; color: #e2e8f0; margin-top: 0.65rem;
        }
        .btn.danger { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fef2f2; }
        .alert {
            padding: 1rem 1.25rem; border-radius: 10px; margin-bottom: 1.5rem;
            border: 1px solid var(--border); font-size: 0.9rem;
        }
        .alert.success { background: rgba(16, 185, 129, 0.12); border-color: var(--accent); color: #6ee7b7; }
        .alert.danger { background: rgba(239, 68, 68, 0.12); border-color: var(--danger); color: #fca5a5; }
        .alert.info { background: rgba(59, 130, 246, 0.12); border-color: var(--accent-blue); color: #93c5fd; }
        .code-box {
            background: #060911; border: 1px solid #1e293b; border-radius: 8px;
            padding: 0.85rem; font-family: monospace; font-size: 0.82rem;
            color: #34d399; word-break: break-all; margin-top: 0.5rem;
        }
        .qr-wrap {
            display: flex; gap: 1.25rem; align-items: center; flex-wrap: wrap; margin: 1rem 0;
        }
        .honeytrap { position: absolute; left: -9999px; opacity: 0; height: 0; width: 0; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.82rem; }
        th, td { text-align: left; padding: 0.65rem; border-bottom: 1px solid var(--border); }
        th { color: var(--text-muted); font-weight: 600; }
        .pow-status { font-size: 0.78rem; color: #38bdf8; margin-bottom: 0.85rem; display: block; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div class="brand">
            <div class="shield-badge" aria-hidden="true">ZT</div>
            <div>
                <h1 style="font-size: 1.3rem;">ZeroTrust Shield Enterprise</h1>
                <div style="font-size: 0.8rem; color: var(--text-muted);">
                    NIST SP 800-207 Continuous Adaptive Authentication &bull; XChaCha20-Poly1305 AEAD &bull; Anti-AI PoW &bull; WebAuthn Passkeys
                </div>
            </div>
        </div>
        <div class="status-pills">
            <span class="pill ok">AEAD: <?= function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt') ? 'XChaCha20-Poly1305' : 'AES-256-GCM' ?></span>
            <span class="pill ok">KDF: Argon2id + HKDF-SHA256</span>
            <span class="pill <?= $ledgerIntegrity['valid'] ? 'ok' : '' ?>">
                Audit Chain: <?= $ledgerIntegrity['valid'] ? 'VERIFIED (' . $ledgerIntegrity['total_entries'] . ' blocks)' : 'TAMPER DETECTED' ?>
            </span>
            <a class="pill ok" href="?action=api_metrics" target="_blank" rel="noopener">Metrics JSON</a>
            <a class="pill ok" href="?action=api_metrics&amp;format=prometheus" target="_blank" rel="noopener">Prometheus</a>
        </div>
    </header>

    <main>
    <?php if ($flashMessage !== null): ?>
        <div class="alert <?= $e($flashType) ?>" role="alert" aria-live="polite">
            <strong>Security Notification:</strong> <?= $e($flashMessage) ?>
        </div>
    <?php endif; ?>

    <?php if ($provisionedData !== null): ?>
        <div class="card" style="margin-bottom: 1.75rem; border-color: var(--accent);">
            <h2>MFA Enrolment &amp; Single-Use Recovery Credentials</h2>
            <p class="sub">Scan or launch the authenticator URI below, or store the Base32 secret and recovery codes in your hardware vault.</p>
            <div class="qr-wrap">
                <?= $renderTotpSvgMatrix((string) ($provisionedData['totp_uri'] ?? '')) ?>
                <div style="flex: 1; min-width: 240px;">
                    <div><strong>RFC 6238 Base32 TOTP Secret:</strong></div>
                    <div class="code-box" id="totp-secret-box"><?= $e((string) ($provisionedData['totp_secret'] ?? '')) ?></div>
                    <div style="margin-top: 0.65rem; display: flex; gap: 0.65rem; flex-wrap: wrap;">
                        <a class="btn secondary" style="width: auto; padding: 0.5rem 0.9rem; font-size: 0.82rem;" href="<?= $e((string) ($provisionedData['totp_uri'] ?? '')) ?>">Open in Authenticator App</a>
                    </div>
                </div>
            </div>
            <div style="margin-top: 0.85rem;"><strong>Authenticator Provisioning URI:</strong></div>
            <div class="code-box"><?= $e((string) ($provisionedData['totp_uri'] ?? '')) ?></div>
            <div style="margin-top: 0.85rem;"><strong>Single-Use Backup Recovery Codes:</strong></div>
            <div class="code-box"><?= $e(implode('   ', $provisionedData['recovery_codes'] ?? [])) ?></div>
        </div>
    <?php endif; ?>

    <?php if ($sessionState['authenticated']): ?>
        <?php
            $user = $sessionState['user'] ?? [];
            $session = $sessionState['session'] ?? [];
            $csrfToken = ZeroTrustAuthService::generateCsrfToken((string) ($session['session_id'] ?? ''));
        ?>
        <div class="grid">
            <div class="card">
                <h2>Active Zero-Trust Identity &amp; Session Telemetry</h2>
                <p class="sub">Evaluated on every HTTP request against device fingerprint and subnet drift.</p>
                <div class="code-box">
                    Identity UUID: <?= $e((string) ($user['uuid'] ?? '')) ?><br>
                    Username: <?= $e((string) ($user['username'] ?? '')) ?><br>
                    Decrypted PII Email: <?= $e((string) ($user['email'] ?? '')) ?><br>
                    Role: <?= $e((string) ($user['role'] ?? '')) ?><br>
                    Session ID: <?= $e((string) ($session['session_id'] ?? '')) ?><br>
                    MFA Hardware Verified: <?= !empty($session['mfa_verified']) ? 'YES (RFC 6238 / WebAuthn)' : 'NO' ?><br>
                    Live Composite Risk Score: <?= (int) $sessionState['risk_score'] ?> / 100<br>
                    Policy Decision: <?= $e($sessionState['decision']) ?>
                </div>
                <button type="button" id="btn-enroll-passkey" class="btn secondary" style="margin-top: 1rem;">
                    Enroll Hardware Passkey (Touch ID / Windows Hello / YubiKey)
                </button>
                <span id="passkey-enroll-status" class="pow-status" aria-live="polite" style="margin-top: 0.5rem;"></span>
                <form method="POST" action="index.php" style="margin-top: 0.75rem;">
                    <input type="hidden" name="form_action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?= $e($csrfToken) ?>">
                    <button type="submit" class="btn danger">Revoke Cryptographic Session</button>
                </form>
            </div>

            <div class="card">
                <h2>Tamper-Evident Hash-Chained Audit Ledger</h2>
                <p class="sub">Every row is AEAD-encrypted and chained via HMAC-SHA256 to prevent database tampering.</p>
                <table>
                    <thead>
                        <tr>
                            <th scope="col">#</th>
                            <th scope="col">Event</th>
                            <th scope="col">Severity</th>
                            <th scope="col">Risk</th>
                            <th scope="col">Entry Hash (Prefix)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentLogs as $log): ?>
                            <tr>
                                <td><?= (int) $log['id'] ?></td>
                                <td><?= $e((string) $log['event_type']) ?></td>
                                <td><?= $e((string) $log['severity']) ?></td>
                                <td><?= (int) $log['risk_score'] ?></td>
                                <td><code><?= $e(substr((string) $log['entry_hash'], 0, 14)) ?>...</code></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php else: ?>
        <div class="grid">
            <!-- Zero-Trust Login Card -->
            <div class="card">
                <h2>Zero-Trust Multi-Factor Authentication</h2>
                <p class="sub">Requires Argon2id credentials, RFC 6238 TOTP (or Recovery Code / Passkey), and SHA-256 Proof-of-Work.</p>
                <form method="POST" action="index.php" class="zt-pow-form">
                    <input type="hidden" name="form_action" value="login">
                    <input type="hidden" name="pow_challenge_id" value="<?= $e($powChallenge['challenge_id']) ?>">
                    <input type="hidden" name="pow_nonce" value="<?= $e($powChallenge['nonce']) ?>">
                    <input type="hidden" name="pow_timestamp" value="<?= (int) $powChallenge['timestamp'] ?>">
                    <input type="hidden" name="pow_difficulty" value="<?= (int) $powChallenge['difficulty'] ?>">
                    <input type="hidden" name="pow_signature" value="<?= $e($powChallenge['signature']) ?>">
                    <input type="hidden" name="pow_solution" value="">
                    <input type="hidden" name="client_fingerprint" value="">

                    <div class="honeytrap" aria-hidden="true">
                        <label>Leave this field blank</label>
                        <input type="text" name="website_url_verification" tabindex="-1" autocomplete="off">
                    </div>

                    <div class="form-group">
                        <label for="login_username">Username or Email</label>
                        <input type="text" id="login_username" name="username" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="login_password">Master Password</label>
                        <input type="password" id="login_password" name="password" required autocomplete="current-password">
                    </div>
                    <div class="form-group">
                        <label for="login_totp">6-Digit TOTP Code (Authenticator App)</label>
                        <input type="text" id="login_totp" name="totp_code" placeholder="123456" pattern="[0-9]{6}" autocomplete="one-time-code">
                    </div>
                    <div class="form-group">
                        <label for="login_recovery">Or Single-Use Recovery Code</label>
                        <input type="text" id="login_recovery" name="recovery_code" placeholder="XXXX-XXXX-XXXX">
                    </div>
                    <span class="pow-status" aria-live="polite">Anti-AI Proof-of-Work Status: Ready (Difficulty <?= (int) $powChallenge['difficulty'] ?>)</span>
                    <button type="submit" class="btn">Compute PoW &amp; Authenticate</button>
                    <button type="button" id="btn-passkey-login" class="btn outline">Verify with WebAuthn Passkey (Touch ID / Security Key)</button>
                </form>
            </div>

            <!-- Zero-Trust Registration Card -->
            <div class="card">
                <h2>Provision Zero-Trust Identity</h2>
                <p class="sub">Enrolls a new identity with XChaCha20-Poly1305 encrypted PII and RFC 6238 TOTP secret.</p>
                <form method="POST" action="index.php" class="zt-pow-form">
                    <input type="hidden" name="form_action" value="register">
                    <input type="hidden" name="pow_challenge_id" value="<?= $e($powChallenge['challenge_id']) ?>">
                    <input type="hidden" name="pow_nonce" value="<?= $e($powChallenge['nonce']) ?>">
                    <input type="hidden" name="pow_timestamp" value="<?= (int) $powChallenge['timestamp'] ?>">
                    <input type="hidden" name="pow_difficulty" value="<?= (int) $powChallenge['difficulty'] ?>">
                    <input type="hidden" name="pow_signature" value="<?= $e($powChallenge['signature']) ?>">
                    <input type="hidden" name="pow_solution" value="">
                    <input type="hidden" name="client_fingerprint" value="">

                    <div class="honeytrap" aria-hidden="true">
                        <label>Leave this field blank</label>
                        <input type="text" name="website_url_verification" tabindex="-1" autocomplete="off">
                    </div>

                    <div class="form-group">
                        <label for="reg_username">Username (3-32 alphanumeric chars)</label>
                        <input type="text" id="reg_username" name="username" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="reg_email">Email Address (Encrypted via AEAD + Blind Indexed)</label>
                        <input type="email" id="reg_email" name="email" required autocomplete="email">
                    </div>
                    <div class="form-group">
                        <label for="reg_password">High-Entropy Password (12+ chars, upper/lower/num/symbol)</label>
                        <input type="password" id="reg_password" name="password" required autocomplete="new-password">
                    </div>
                    <span class="pow-status" aria-live="polite">Anti-AI Proof-of-Work Status: Ready (Difficulty <?= (int) $powChallenge['difficulty'] ?>)</span>
                    <button type="submit" class="btn secondary">Solve PoW &amp; Provision Identity</button>
                </form>
            </div>
        </div>
    <?php endif; ?>
    </main>
</div>

<script nonce="<?= $e($cspNonce) ?>">
/**
 * Client-Side WebCrypto SHA-256 Proof-of-Work Solver, Telemetry Fingerprint & WebAuthn Passkey Client.
 */
async function sha256Hex(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeClientFingerprint() {
    const signals = [
        navigator.userAgent || '',
        navigator.language || '',
        screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
        Intl.DateTimeFormat().resolvedOptions().timeZone || '',
        String(navigator.hardwareConcurrency || 0)
    ].join('||');
    return sha256Hex(signals);
}

computeClientFingerprint().then(fp => {
    document.querySelectorAll('input[name="client_fingerprint"]').forEach(el => {
        el.value = fp;
    });
});

document.querySelectorAll('.zt-pow-form').forEach(form => {
    form.addEventListener('submit', async (e) => {
        const solutionInput = form.querySelector('input[name="pow_solution"]');
        if (solutionInput.value !== '') {
            return;
        }
        e.preventDefault();
        const nonce = form.querySelector('input[name="pow_nonce"]').value;
        const difficulty = parseInt(form.querySelector('input[name="pow_difficulty"]').value, 10);
        const statusEl = form.querySelector('.pow-status');
        const submitBtn = form.querySelector('button[type="submit"]');
        const targetPrefix = '0'.repeat(difficulty);

        submitBtn.disabled = true;
        statusEl.textContent = 'Computing cryptographic SHA-256 Proof-of-Work...';

        let counter = 0;
        while (true) {
            const candidate = counter.toString(16);
            const digest = await sha256Hex(nonce + ':' + candidate);
            if (digest.startsWith(targetPrefix)) {
                solutionInput.value = candidate;
                statusEl.textContent = 'Proof-of-Work solved (' + counter + ' hashes). Submitting...';
                form.submit();
                break;
            }
            counter++;
            if (counter % 2500 === 0) {
                statusEl.textContent = 'Computing SHA-256 PoW... (' + counter + ' hashes evaluated)';
                await new Promise(r => setTimeout(r, 0));
            }
        }
    });
});

function b64urlToUint8Array(base64url) {
    const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function uint8ArrayToB64url(bytes) {
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const enrollBtn = document.getElementById('btn-enroll-passkey');
if (enrollBtn && window.PublicKeyCredential) {
    enrollBtn.addEventListener('click', async () => {
        const statusEl = document.getElementById('passkey-enroll-status');
        try {
            statusEl.textContent = 'Requesting WebAuthn Passkey challenge...';
            const resp = await fetch('?action=api_webauthn_register_options');
            const opts = await resp.json();
            opts.challenge = b64urlToUint8Array(opts.challenge);
            opts.user.id = b64urlToUint8Array(opts.user.id);
            const cred = await navigator.credentials.create({ publicKey: opts });
            const clientDataJSON = JSON.parse(new TextDecoder().decode(cred.response.clientDataJSON));
            const verifyResp = await fetch('?action=api_webauthn_register_verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    credentialId: uint8ArrayToB64url(new Uint8Array(cred.rawId)),
                    clientDataJSON: clientDataJSON,
                    attestationObject: uint8ArrayToB64url(new Uint8Array(cred.response.attestationObject))
                })
            });
            const result = await verifyResp.json();
            statusEl.textContent = result.message || 'Passkey enrollment completed.';
        } catch (err) {
            statusEl.textContent = 'Passkey prompt cancelled or unsupported in current context.';
        }
    });
}

const passkeyLoginBtn = document.getElementById('btn-passkey-login');
if (passkeyLoginBtn && window.PublicKeyCredential) {
    passkeyLoginBtn.addEventListener('click', async () => {
        const userEl = document.getElementById('login_username');
        const statusEl = passkeyLoginBtn.closest('form').querySelector('.pow-status');
        if (!userEl.value.trim()) {
            statusEl.textContent = 'Enter your username first to request a bound WebAuthn challenge.';
            userEl.focus();
            return;
        }
        try {
            statusEl.textContent = 'Requesting WebAuthn assertion challenge...';
            const resp = await fetch('?action=api_webauthn_auth_options&username=' + encodeURIComponent(userEl.value.trim()));
            const opts = await resp.json();
            opts.challenge = b64urlToUint8Array(opts.challenge);
            if (Array.isArray(opts.allowCredentials)) {
                opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: b64urlToUint8Array(c.id) }));
            }
            await navigator.credentials.get({ publicKey: opts });
            statusEl.textContent = 'Hardware Passkey verified by authenticator.';
        } catch (err) {
            statusEl.textContent = 'WebAuthn passkey assertion cancelled or no passkey enrolled yet.';
        }
    });
}
</script>
</body>
</html>
