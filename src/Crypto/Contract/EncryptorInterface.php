<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Contract;

interface EncryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string;
}
