<?php

declare(strict_types=1);

namespace ZeroTrust\Tests;

use PHPUnit\Framework\TestCase;
use ZeroTrust\Crypto\CryptoEngine;

final class CryptoEngineTest extends TestCase
{
    public function testAeadRoundTrip(): void
    {
        $plain = 'secret-payload-42';
        $aad   = 'user:99|ctx:test';
        $cipher = CryptoEngine::encrypt($plain, $aad, 'unit-test');
        $this->assertSame($plain, CryptoEngine::decrypt($cipher, $aad, 'unit-test'));
    }

    public function testAeadRejectsTamperedAad(): void
    {
        $cipher = CryptoEngine::encrypt('data', 'correct-aad', 'unit-test');
        $this->expectException(\RuntimeException::class);
        CryptoEngine::decrypt($cipher, 'wrong-aad', 'unit-test');
    }

    public function testPasswordHashing(): void
    {
        $password = 'Correct#Horse$Battery99!';
        $hash = CryptoEngine::hashPassword($password);
        $this->assertTrue(CryptoEngine::verifyPassword($password, $hash));
        $this->assertFalse(CryptoEngine::verifyPassword('WrongPassword', $hash));
    }

    public function testBlindIndexIsDeterministicAndDomainSeparated(): void
    {
        $a = CryptoEngine::blindIndex('alice@example.com', 'email');
        $b = CryptoEngine::blindIndex('alice@example.com', 'email');
        $c = CryptoEngine::blindIndex('alice@example.com', 'other');
        $this->assertSame($a, $b);
        $this->assertNotSame($a, $c);
    }

    public function testSignAndVerify(): void
    {
        $msg = 'test-message';
        $sig = CryptoEngine::sign($msg, 'unit-test');
        $this->assertTrue(CryptoEngine::verifySignature($msg, $sig, 'unit-test'));
        $this->assertFalse(CryptoEngine::verifySignature($msg, $sig, 'different-purpose'));
    }
}
