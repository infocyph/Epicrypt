<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\BaseProtectionContext;
use Infocyph\Epicrypt\Internal\ContextValue;

/**
 * @internal
 */
final readonly class ProtectionContext extends BaseProtectionContext
{
    public function __construct(
        public ?string $purpose = null,
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
        $baseFields = ContextValue::baseProtectionFields(
            $context,
            fn(string $key): ConfigurationException => new ConfigurationException(sprintf('Protection context %s must be a boolean.', $key)),
            fn(string $key): ConfigurationException => new ConfigurationException(sprintf('Protection context %s must be a string.', $key)),
            fn(string $key): ConfigurationException => new ConfigurationException(sprintf('Protection context %s must be a non-empty string when provided.', $key)),
        );
        $purpose = ContextValue::optionalNonEmptyString(
            $context,
            'purpose',
            fn(string $key): ConfigurationException => new ConfigurationException(sprintf('Protection context %s must be a non-empty string when provided.', $key)),
        );

        return new self(
            purpose: $purpose,
            keyIsBinary: $baseFields['key_is_binary'],
            nonceIsBinary: $baseFields['nonce_is_binary'],
            aad: $baseFields['aad'],
            keyId: $baseFields['key_id'],
        );
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public static function normalize(array $context): array
    {
        return array_merge($context, self::fromArray($context)->toArray());
    }

    /**
     * @return array{key_is_binary: bool, nonce_is_binary: bool, aad: string, key_id?: string, purpose?: string}
     */
    public function toArray(): array
    {
        $normalized = [
            'key_is_binary' => $this->keyIsBinary,
            'nonce_is_binary' => $this->nonceIsBinary,
            'aad' => $this->aad,
        ];

        if ($this->keyId !== null) {
            $normalized['key_id'] = $this->keyId;
        }

        if ($this->purpose !== null) {
            $normalized['purpose'] = $this->purpose;
        }

        return $normalized;
    }
}
