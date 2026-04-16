<?php

namespace Infocyph\Epicrypt\Crypto\Contract;

interface DecryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string;
}
