<?php

namespace Infocyph\Epicrypt\Crypto\Contract;

interface MacInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function generate(string $message, string $key, array $context = []): string;

    public function generateKey(bool $asBase64Url = true): string;

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $mac, string $key, array $context = []): bool;
}
