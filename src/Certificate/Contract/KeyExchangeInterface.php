<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

interface KeyExchangeInterface
{
    public function deriveSharedSecret(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
    ): string;

    public function deriveSharedSecretFromBinaryKeys(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
    ): string;
}
