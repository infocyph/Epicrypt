<?php

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;

final readonly class KeyExchange implements KeyExchangeInterface
{
    public function __construct(
        private KeyExchangeInterface $backend,
    ) {}

    public static function openSsl(): self
    {
        return new self(new OpenSSL\DiffieHellman());
    }

    public static function sodium(): self
    {
        return new self(new Sodium\SessionKeyExchange());
    }

    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string
    {
        return $this->backend->derive($privateKey, $publicKey, $keysAreBinary);
    }
}
