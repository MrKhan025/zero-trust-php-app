<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Crypto\TotpAuthenticator;

final class TotpAuthenticatorTest extends TestCase
{
    public function testGenerateAndVerify(): void
    {
        $secret = TotpAuthenticator::generateSecret();
        $time = 1700000000;
        $code = TotpAuthenticator::getCode($secret, $time);

        $this->assertTrue(TotpAuthenticator::verifyCode($secret, $code, 1, $time));
        $this->assertFalse(TotpAuthenticator::verifyCode($secret, '000000', 0, $time));
    }

    public function testRecoveryCodesAreSingleUse(): void
    {
        $rec = TotpAuthenticator::generateRecoveryCodes(4);
        $first = $rec['plaintext'][0];

        $r1 = TotpAuthenticator::consumeRecoveryCode($first, $rec['hashes']);
        $this->assertTrue($r1['valid']);
        $this->assertCount(3, $r1['remaining']);

        $r2 = TotpAuthenticator::consumeRecoveryCode($first, $r1['remaining']);
        $this->assertFalse($r2['valid']);
    }
}
