<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Enum;

use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;

enum AsymmetricJwtAlgorithm: string
{
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';

    public static function fromHeader(string $algorithm): self
    {
        $resolved = self::tryFrom(strtoupper($algorithm));
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
            self::RS256,
            self::RS384,
            self::RS512 => null,
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
        };
    }
}
