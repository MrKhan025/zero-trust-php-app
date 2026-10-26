<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PDO;
use ZeroTrust\Audit\AuditLedger;
use ZeroTrust\Auth\ZeroTrustAuthService;
use ZeroTrust\Bootstrap;
use ZeroTrust\Core\Database;
use ZeroTrust\Crypto\CryptoEngine;
use ZeroTrust\Crypto\TotpAuthenticator;
use ZeroTrust\Defense\BotDefenseGuard;
use ZeroTrust\Defense\WafMiddleware;
use ZeroTrust\Policy\ZeroTrustPolicyEngine;

require_once dirname(__DIR__) . '/src/Bootstrap.php';
Bootstrap::init(dirname(__DIR__));

// Bind an isolated in-memory SQLite database for deterministic testing
$memoryPdo = new PDO('sqlite::memory:');
Database::setConnection($memoryPdo);

final class SecurityTestRunner
{
    private int $passed = 0;
    private int $failed = 0;

    public function assert(bool $condition, string $testName): void
    {
        if ($condition) {
            $this->passed++;
            echo "  [PASS] {$testName}\n";
        } else {
            $this->failed++;
            echo "  [FAIL] {$testName}\n";
        }
    }

    public function summary(): int
    {
        echo "\n====================================================================\n";
        echo " Security Test Results: {$this->passed} Passed, {$this->failed} Failed\n";
        echo "====================================================================\n";
        return $this->failed === 0 ? 0 : 1;
    }
}

$runner = new SecurityTestRunner();
echo "====================================================================\n";
echo " ZERO-TRUST PHP SECURITY & ADVERSARIAL VERIFICATION SUITE\n";
echo "====================================================================\n\n";

// 1. Test AEAD Encryption & Tamper Detection
$plaintext = 'classified-financial-record-9941';
$aad = 'user:42|record:9941';
$ciphertext = CryptoEngine::encrypt($plaintext, $aad, 'test-context');
$decrypted = CryptoEngine::decrypt($ciphertext, $aad, 'test-context');
$runner->assert($decrypted === $plaintext, 'AEAD XChaCha20-Poly1305 / AES-256-GCM encrypts and decrypts cleanly');

$tamperedAadCaught = false;
try {
    CryptoEngine::decrypt($ciphertext, 'user:99|record:9941', 'test-context');
} catch (\Throwable) {
    $tamperedAadCaught = true;
}
$runner->assert($tamperedAadCaught, 'AEAD immediately rejects modified Associated Authenticated Data (AAD)');

// 2. Test Argon2id + HMAC-SHA256 Peppering
$password = 'Correct#Horse$Battery99!';
$hash = CryptoEngine::hashPassword($password);
$runner->assert(CryptoEngine::verifyPassword($password, $hash), 'Argon2id + HMAC-SHA256 pepper verifies valid password');
$runner->assert(!CryptoEngine::verifyPassword('Wrong#Horse$Battery99!', $hash), 'Argon2id rejects invalid password');

// 3. Test RFC 6238 TOTP & Recovery Codes
$totpSecret = TotpAuthenticator::generateSecret();
$fixedTime = 1700000000;
$code = TotpAuthenticator::getCode($totpSecret, $fixedTime);
$runner->assert(TotpAuthenticator::verifyCode($totpSecret, $code, 1, $fixedTime), 'RFC 6238 TOTP verifies valid 6-digit code');
$runner->assert(!TotpAuthenticator::verifyCode($totpSecret, '000000', 0, $fixedTime), 'RFC 6238 TOTP rejects invalid code');

$rec = TotpAuthenticator::generateRecoveryCodes(4);
$firstCode = $rec['plaintext'][0];
$consume1 = TotpAuthenticator::consumeRecoveryCode($firstCode, $rec['hashes']);
$runner->assert($consume1['valid'] && count($consume1['remaining']) === 3, 'Recovery code is validated and consumed once');
$consume2 = TotpAuthenticator::consumeRecoveryCode($firstCode, $consume1['remaining']);
$runner->assert(!$consume2['valid'], 'Replayed recovery code is strictly rejected');

// 4. Test Anti-AI Proof-of-Work (PoW) Challenge & Replay Defense
$clientIp = '203.0.113.45';
$challenge = BotDefenseGuard::issueChallenge($clientIp);
$solution = '';
$prefix = str_repeat('0', $challenge['difficulty']);
for ($i = 0; $i < 5000000; $i++) {
    $cand = dechex($i);
    if (str_starts_with(hash('sha256', $challenge['nonce'] . ':' . $cand), $prefix)) {
        $solution = $cand;
        break;
    }
}
$powPayload = [
    'pow_challenge_id' => $challenge['challenge_id'],
    'pow_nonce' => $challenge['nonce'],
    'pow_timestamp' => $challenge['timestamp'],
    'pow_difficulty' => $challenge['difficulty'],
    'pow_signature' => $challenge['signature'],
    'pow_solution' => $solution,
    'website_url_verification' => '',
];
$verify1 = BotDefenseGuard::verifySubmission($powPayload, $clientIp);
$runner->assert($verify1['passed'], 'Stateless SHA-256 Proof-of-Work challenge solved and verified');

$verifyReplay = BotDefenseGuard::verifySubmission($powPayload, $clientIp);
$runner->assert(!$verifyReplay['passed'] && $verifyReplay['reason'] === 'POW_CHALLENGE_REPLAYED', 'Replayed Proof-of-Work token is blocked');

// 5. Test Full Identity Registration, MFA Login, and Zero-Trust Session Binding
$reg = ZeroTrustAuthService::registerUser([
    'username' => 'alice_secops',
    'email' => 'alice@zerotrust.internal',
    'password' => 'Ultra$ecureZeroTrust2026!',
], $clientIp, false);
$runner->assert($reg['success'], 'Zero-Trust identity provisioned with encrypted PII & TOTP');

$liveTotp = TotpAuthenticator::getCode((string) $reg['totp_secret']);
$serverContext = [
    'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) ZeroTrustBrowser/1.0',
    'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
    'HTTP_SEC_CH_UA_PLATFORM' => '"Linux"',
];

$auth = ZeroTrustAuthService::authenticate([
    'username' => 'alice_secops',
    'password' => 'Ultra$ecureZeroTrust2026!',
    'totp_code' => $liveTotp,
], $clientIp, $serverContext, false);
$runner->assert($auth['success'] && isset($auth['session_token']), 'Multi-Factor Authentication issues bound Zero-Trust session');

// Verify normal request evaluation
$evalNormal = ZeroTrustAuthService::verifyAndEvaluateSession($auth['session_token'], $clientIp, $serverContext);
$runner->assert(
    $evalNormal['authenticated'] && $evalNormal['decision'] === ZeroTrustPolicyEngine::DECISION_ALLOW && $evalNormal['risk_score'] === 0,
    'Zero-Trust Policy Engine allows matching Device Fingerprint + IP Subnet (Risk = 0)'
);

// Simulate Session Cookie Hijack from a different Device + different IP Subnet
$hijackerServer = [
    'HTTP_USER_AGENT' => 'python-requests/2.31.0',
    'HTTP_ACCEPT_LANGUAGE' => 'ru-RU',
    'HTTP_SEC_CH_UA_PLATFORM' => '"Windows"',
];
$evalHijack = ZeroTrustAuthService::verifyAndEvaluateSession($auth['session_token'], '198.51.100.99', $hijackerServer);
$runner->assert(
    !$evalHijack['authenticated'] && $evalHijack['decision'] === ZeroTrustPolicyEngine::DECISION_DENY_TERMINATE,
    'Zero-Trust Policy Engine automatically revokes stolen session upon Device + IP Subnet drift'
);

// 6. Test WAF Middleware Payload Blocking
$sqliCheck = WafMiddleware::inspectRequest(['id' => "1' UNION ALL SELECT username,password_hash FROM users--"], [], []);
$runner->assert($sqliCheck['blocked'] && $sqliCheck['rule'] === 'SQL_INJECTION', 'WAF blocks SQL Injection payload');

$xssCheck = WafMiddleware::inspectRequest([], ['comment' => '<script>fetch("https://evil.tld")</script>'], []);
$runner->assert($xssCheck['blocked'] && $xssCheck['rule'] === 'XSS_ATTACK', 'WAF blocks Cross-Site Scripting (XSS) payload');

// 7. Test Hash-Chained Audit Ledger Verification
$chainStatus = AuditLedger::verifyChainIntegrity();
$runner->assert($chainStatus['valid'] && $chainStatus['total_entries'] > 0, 'Cryptographic Hash-Chained Audit Ledger passes full integrity verification');

exit($runner->summary());
