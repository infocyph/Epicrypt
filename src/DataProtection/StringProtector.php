<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;

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
        return $this->cipher->decrypt($ciphertext, $key, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        return $this->cipher->encrypt($plaintext, $key, $context);
    }
}
