<?php

namespace Infocyph\Epicrypt\DataProtection\String;

use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBox\Encryptor as SecretBoxEncryptor;

final readonly class StringEncryptor implements EncryptorInterface
{
    public function __construct(
        private SecretBoxEncryptor $encryptor = new SecretBoxEncryptor(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        return $this->encryptor->encrypt($plaintext, $key, $context);
    }
}
