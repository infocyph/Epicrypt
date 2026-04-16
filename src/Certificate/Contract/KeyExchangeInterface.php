<?php

namespace Infocyph\Epicrypt\Certificate\Contract;

interface KeyExchangeInterface
{
    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string;
}
