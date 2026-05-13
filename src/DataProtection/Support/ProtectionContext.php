<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;

/**
 * @internal
 */
final readonly class ProtectionContext
{
    public function __construct(
        public bool $keyIsBinary = false,
        public bool $nonceIsBinary = false,
        public string $aad = '',
        public ?string $keyId = null,
        public ?string $purpose = null,
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public static function fromArray(array $context): self
    {
        $keyIsBinary = $context['key_is_binary'] ?? false;
        if (!is_bool($keyIsBinary)) {
            throw new ConfigurationException('Protection context key_is_binary must be a boolean.');
        }

        $nonceIsBinary = $context['nonce_is_binary'] ?? false;
        if (!is_bool($nonceIsBinary)) {
            throw new ConfigurationException('Protection context nonce_is_binary must be a boolean.');
        }

        $aad = $context['aad'] ?? '';
        if (!is_string($aad)) {
            throw new ConfigurationException('Protection context aad must be a string.');
        }

        $keyId = $context['key_id'] ?? null;
        if ($keyId !== null && (!is_string($keyId) || $keyId === '')) {
            throw new ConfigurationException('Protection context key_id must be a non-empty string when provided.');
        }

        $purpose = $context['purpose'] ?? null;
        if ($purpose !== null && (!is_string($purpose) || $purpose === '')) {
            throw new ConfigurationException('Protection context purpose must be a non-empty string when provided.');
        }

        return new self($keyIsBinary, $nonceIsBinary, $aad, $keyId, $purpose);
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
