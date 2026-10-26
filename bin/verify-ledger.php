#!/usr/bin/env php
<?php

declare(strict_types=1);

use ZeroTrust\Audit\AuditLedger;
use ZeroTrust\Bootstrap;

require_once dirname(__DIR__) . '/src/Bootstrap.php';
Bootstrap::init(dirname(__DIR__));

$args = $argv ?? [];

if (in_array('--generate-keys', $args, true)) {
    echo "====================================================================\n";
    echo " ZERO-TRUST 256-BIT CRYPTOGRAPHIC KEY GENERATOR (CSPRNG)\n";
    echo "====================================================================\n";
    echo "ZT_MASTER_ENCRYPTION_KEY=\"" . bin2hex(random_bytes(32)) . "\"\n";
    echo "ZT_AUTH_PEPPER_SECRET=\"" . bin2hex(random_bytes(32)) . "\"\n";
    echo "ZT_TOKEN_SIGNING_KEY=\"" . bin2hex(random_bytes(32)) . "\"\n";
    echo "====================================================================\n";
    exit(0);
}

echo "[*] Verifying Zero-Trust Hash-Chained Audit Ledger & AEAD Tags...\n";
$report = AuditLedger::verifyChainIntegrity();

if ($report['valid']) {
    echo "[OK] Ledger Integrity Verified: {$report['total_entries']} cryptographic blocks authenticated.\n";
    exit(0);
}

fwrite(STDERR, "[CRITICAL] TAMPERING DETECTED at Entry #{$report['broken_at_id']}: {$report['error']}\n");
exit(1);
