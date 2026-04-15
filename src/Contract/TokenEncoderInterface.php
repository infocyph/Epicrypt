<?php

namespace Infocyph\Epicrypt\Contract;

interface TokenEncoderInterface
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function encode(array $claims, mixed $key, array $headers = []): string;
}
