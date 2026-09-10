<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Enum;

use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;

enum SymmetricJwtAlgorithm: string
{
    case HS256 = 'HS256';

    case HS384 = 'HS384';

    case HS512 = 'HS512';

    public static function fromHeader(string $algorithm): self
    {
        $resolved = self::tryFrom($algorithm);
        if ($resolved === null) {
            throw new UnsupportedAlgorithmException('Unsupported symmetric JWT algorithm: ' . $algorithm);
        }

        return $resolved;
    }

    public function hmacAlgorithm(): string
    {
        return match ($this) {
            self::HS256 => 'sha256',
            self::HS384 => 'sha384',
            self::HS512 => 'sha512',
        };
    }

    public function minimumKeyBytes(): int
    {
        return match ($this) {
            self::HS256 => 32,
            self::HS384 => 48,
            self::HS512 => 64,
        };
    }
}
