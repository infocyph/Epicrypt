<?php

namespace Infocyph\Epicrypt\DataProtection\String;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBox\Decryptor as SecretBoxDecryptor;

final readonly class StringDecryptor implements DecryptorInterface
{
    public function __construct(
        private SecretBoxDecryptor $decryptor = new SecretBoxDecryptor(),
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        return $this->decryptor->decrypt($ciphertext, $key, $context);
    }
}
