<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

/**
 * @internal
 */
final readonly class KeyDerivationContext
{
    public function __construct(
        public SecurityProfile $profile = SecurityProfile::MODERN,
        public bool $saltIsBinary = false,
        public bool $asBase64Url = true,
        public bool $inputKeyMaterialIsBinary = false,
        public bool $rootKeyIsBinary = false,
        public ?int $opslimit = null,
        public ?int $memlimit = null,
        public string $algorithm = 'sha256',
        public string $info = '',
        public string $sodiumContext = 'EPCKDF01',
        public ?string $salt = null,
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public static function fromArray(array $context): self
    {
        $profile = $context['profile'] ?? SecurityProfile::MODERN;
        if (!$profile instanceof SecurityProfile) {
            throw new ConfigurationException('Derivation profile must be a SecurityProfile enum.');
        }

        $saltIsBinary = self::bool($context, 'salt_is_binary', false);
        $asBase64Url = self::bool($context, 'as_base64url', true);
        $inputKeyMaterialIsBinary = self::bool($context, 'input_key_material_is_binary', false);
        $rootKeyIsBinary = self::bool($context, 'root_key_is_binary', false);

        $opslimit = self::nullablePositiveInt($context, 'opslimit');
        $memlimit = self::nullablePositiveInt($context, 'memlimit');

        $algorithm = self::string($context, 'algorithm', 'sha256');
        $info = self::string($context, 'info', '');
        $sodiumContext = self::string($context, 'context', 'EPCKDF01');

        $salt = $context['salt'] ?? null;
        if ($salt !== null && !is_string($salt)) {
            throw new ConfigurationException('HKDF salt must be a string.');
        }

        return new self(
            profile: $profile,
            saltIsBinary: $saltIsBinary,
            asBase64Url: $asBase64Url,
            inputKeyMaterialIsBinary: $inputKeyMaterialIsBinary,
            rootKeyIsBinary: $rootKeyIsBinary,
            opslimit: $opslimit,
            memlimit: $memlimit,
            algorithm: $algorithm,
            info: $info,
            sodiumContext: $sodiumContext,
            salt: $salt,
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function bool(array $context, string $key, bool $default): bool
    {
        $value = $context[$key] ?? $default;
        if (!is_bool($value)) {
            throw new ConfigurationException(sprintf('Context value "%s" must be boolean.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function nullablePositiveInt(array $context, string $key): ?int
    {
        if (!array_key_exists($key, $context) || $context[$key] === null) {
            return null;
        }

        if (!is_int($context[$key]) || $context[$key] < 1) {
            throw new ConfigurationException(sprintf('Context value "%s" must be a positive integer when provided.', $key));
        }

        return $context[$key];
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function string(array $context, string $key, string $default): string
    {
        $value = $context[$key] ?? $default;
        if (!is_string($value)) {
            throw new ConfigurationException(sprintf('Context value "%s" must be a string.', $key));
        }

        return $value;
    }
}
