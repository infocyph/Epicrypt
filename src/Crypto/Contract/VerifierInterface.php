<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Contract;

interface VerifierInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool;
}
