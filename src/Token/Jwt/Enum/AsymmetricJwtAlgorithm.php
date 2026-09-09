<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Enum;

use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;

enum AsymmetricJwtAlgorithm: string
{
    case EDDSA = 'EdDSA';

    case ES256 = 'ES256';

    case ES384 = 'ES384';

    case ES512 = 'ES512';

    case PS256 = 'PS256';

    case PS384 = 'PS384';

    case PS512 = 'PS512';

    case RS256 = 'RS256';

    case RS384 = 'RS384';

    case RS512 = 'RS512';

    public static function fromHeader(string $algorithm): self
    {
        $resolved = self::tryFrom($algorithm);
        if ($resolved === null) {
            throw new UnsupportedAlgorithmException('Unsupported asymmetric JWT algorithm: ' . $algorithm);
        }

        return $resolved;
    }

    public function ecdsaSignatureLength(): ?int
    {
        return match ($this) {
            self::ES256 => 64,
            self::ES384 => 96,
            self::ES512 => 132,
            self::EDDSA,
            self::PS256,
            self::PS384,
            self::PS512,
            self::RS256,
            self::RS384,
            self::RS512 => null,
        };
    }

    public function hashAlgorithm(): string
    {
        return match ($this) {
            self::ES256, self::PS256, self::RS256 => 'sha256',
            self::ES384, self::PS384, self::RS384 => 'sha384',
            self::ES512, self::PS512, self::RS512 => 'sha512',
            self::EDDSA => 'sha512',
        };
    }

    public function isEc(): bool
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => true,
            default => false,
        };
    }

    public function isEdDsa(): bool
    {
        return $this === self::EDDSA;
    }

    public function isRsa(): bool
    {
        return match ($this) {
            self::PS256,
            self::PS384,
            self::PS512,
            self::RS256,
            self::RS384,
            self::RS512 => true,
            default => false,
        };
    }

    public function isRsaPss(): bool
    {
        return match ($this) {
            self::PS256, self::PS384, self::PS512 => true,
            default => false,
        };
    }

    public function opensslAlgorithm(): int
    {
        return match ($this) {
            self::RS256,
            self::ES256 => OPENSSL_ALGO_SHA256,
            self::RS384,
            self::ES384 => OPENSSL_ALGO_SHA384,
            self::RS512,
            self::ES512 => OPENSSL_ALGO_SHA512,
            self::EDDSA,
            self::PS256,
            self::PS384,
            self::PS512 => throw new UnsupportedAlgorithmException('The selected JWT algorithm does not use OpenSSL signing.'),
        };
    }
}
