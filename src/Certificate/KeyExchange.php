<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;

final readonly class KeyExchange implements KeyExchangeInterface
{
    private function __construct(
        private KeyExchangeInterface $backend,
        private KeyExchangeBackend $backendType,
    ) {}

    public static function forBackend(KeyExchangeBackend $backend): self
    {
        return match ($backend) {
            KeyExchangeBackend::OPENSSL => new self(new OpenSSL\DiffieHellman(), KeyExchangeBackend::OPENSSL),
            KeyExchangeBackend::SODIUM => new self(new Sodium\SessionKeyExchange(), KeyExchangeBackend::SODIUM),
        };
    }

    public static function openSsl(): self
    {
        return self::forBackend(KeyExchangeBackend::OPENSSL);
    }

    public static function sodium(): self
    {
        return self::forBackend(KeyExchangeBackend::SODIUM);
    }

    public function backend(): KeyExchangeBackend
    {
        return $this->backendType;
    }

    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string
    {
        return $this->backend->derive($privateKey, $publicKey, $keysAreBinary);
    }
}
