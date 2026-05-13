<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Context;

use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;

/**
 * @internal
 */
final readonly class AeadContext
{
    public function __construct(
        public bool $keyIsBinary = false,
        public bool $nonceIsBinary = false,
        public string $aad = '',
        public ?string $nonce = null,
        public ?string $keyId = null,
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public static function fromArray(array $context): self
    {
        $keyIsBinary = $context['key_is_binary'] ?? false;
        if (!is_bool($keyIsBinary)) {
            throw new CryptoException('Context value "key_is_binary" must be boolean.');
        }

        $nonceIsBinary = $context['nonce_is_binary'] ?? false;
        if (!is_bool($nonceIsBinary)) {
            throw new CryptoException('Context value "nonce_is_binary" must be boolean.');
        }

        $aad = $context['aad'] ?? '';
        if (!is_string($aad)) {
            throw new CryptoException('AAD must be a string.');
        }

        $nonce = $context['nonce'] ?? null;
        if ($nonce !== null && (!is_string($nonce) || $nonce === '')) {
            throw new InvalidNonceException('Nonce must be a non-empty string.');
        }

        $keyId = $context['key_id'] ?? null;
        if ($keyId !== null && (!is_string($keyId) || $keyId === '')) {
            throw new CryptoException('Context value "key_id" must be a non-empty string when provided.');
        }

        return new self($keyIsBinary, $nonceIsBinary, $aad, $nonce, $keyId);
    }
}
