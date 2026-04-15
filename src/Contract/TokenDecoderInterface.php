<?php

namespace Infocyph\Epicrypt\Contract;

interface TokenDecoderInterface
{
    /**
     * @return array<string, mixed>|object
     */
    public function decode(string $token, mixed $key): array|object;
}
