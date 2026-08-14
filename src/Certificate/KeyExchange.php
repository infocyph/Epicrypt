<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class KeyExchange
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

    public function deriveBinaryKey(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
        int $length,
        string $context,
        string $salt = '',
    ): string {
        return $this->derive($privateKey, $publicKey, $length, $context, $salt, false);
    }

    public function deriveBinaryKeyFromBinaryKeys(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
        int $length,
        string $context,
        string $salt = '',
    ): string {
        return $this->derive($privateKey, $publicKey, $length, $context, $salt, true);
    }

    public function deriveKey(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
        int $length,
        string $context,
        string $salt = '',
    ): string {
        return Base64Url::encode($this->derive($privateKey, $publicKey, $length, $context, $salt, false));
    }

    public function deriveKeyFromBinaryKeys(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
        int $length,
        string $context,
        string $salt = '',
    ): string {
        return Base64Url::encode($this->derive($privateKey, $publicKey, $length, $context, $salt, true));
    }

    private function derive(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
        int $length,
        string $context,
        string $salt,
        bool $binaryInput,
    ): string {
        if ($length < 16 || $length > 64) {
            throw new ConfigurationException('Derived key length must be between 16 and 64 bytes.');
        }
        if ($context === '' || str_contains($context, "\0")) {
            throw new ConfigurationException('Key derivation context must be non-empty and cannot contain NUL.');
        }

        $secret = $binaryInput
            ? $this->backend->deriveSharedSecretFromBinaryKeys($privateKey, $publicKey)
            : $this->backend->deriveSharedSecret($privateKey, $publicKey);

        try {
            return hash_hkdf('sha512', $secret, $length, $context, $salt);
        } finally {
            sodium_memzero($secret);
        }
    }
}
