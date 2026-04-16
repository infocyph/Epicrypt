<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Crypto\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\DataProtection\Support\ProtectionContext;

final readonly class StringProtector implements EncryptorInterface, DecryptorInterface
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        return $this->cipher->decrypt($ciphertext, $key, ProtectionContext::normalize($context));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        return $this->cipher->encrypt($plaintext, $key, ProtectionContext::normalize($context));
    }
}
