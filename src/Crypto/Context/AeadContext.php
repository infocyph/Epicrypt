<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Context;

use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Internal\BaseProtectionContext;
use Infocyph\Epicrypt\Internal\ContextValue;

/**
 * @internal
 */
final readonly class AeadContext extends BaseProtectionContext
{
    public function __construct(
        public ?string $nonce = null,
        bool $keyIsBinary = false,
        bool $nonceIsBinary = false,
        string $aad = '',
        ?string $keyId = null,
    ) {
        parent::__construct($keyIsBinary, $nonceIsBinary, $aad, $keyId);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function fromArray(array $context): self
    {
        $baseFields = self::parseBaseFields($context);

        $nonce = $context['nonce'] ?? null;
        if ($nonce !== null && (!is_string($nonce) || $nonce === '')) {
            throw new InvalidNonceException('Nonce must be a non-empty string.');
        }

        return new self(
            nonce: $nonce,
            keyIsBinary: $baseFields['key_is_binary'],
            nonceIsBinary: $baseFields['nonce_is_binary'],
            aad: $baseFields['aad'],
            keyId: $baseFields['key_id'],
        );
    }

    /**
     * @param array<string, mixed> $context
     * @return array{key_is_binary: bool, nonce_is_binary: bool, aad: string, key_id: ?string}
     */
    private static function parseBaseFields(array $context): array
    {
        return ContextValue::baseProtectionFields(
            $context,
            fn(string $key): CryptoException => new CryptoException(sprintf('Context value "%s" must be boolean.', $key)),
            fn(string $key): CryptoException => new CryptoException(sprintf('Context value "%s" must be a string.', $key)),
            fn(string $key): CryptoException => new CryptoException(sprintf('Context value "%s" must be a non-empty string when provided.', $key)),
        );
    }
}
