<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

interface KeyExchangeInterface
{
    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string;
}
