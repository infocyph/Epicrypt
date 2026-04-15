<?php

namespace Infocyph\Epicrypt\Contract;

interface SignerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function sign(string $message, mixed $key, array $context = []): string;
}
