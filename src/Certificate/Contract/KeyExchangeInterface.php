<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

interface KeyExchangeInterface
{
    public function deriveSharedSecret(string $privateKey, string $publicKey, bool $keysAreBinary): string;
}
