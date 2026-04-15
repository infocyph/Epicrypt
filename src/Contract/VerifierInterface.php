<?php

namespace Infocyph\Epicrypt\Contract;

interface VerifierInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool;
}
