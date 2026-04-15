<?php

namespace Infocyph\Epicrypt\Contract;

interface EncryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string;
}
