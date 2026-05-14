<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final readonly class JwtIssueClaims
{
    public function __construct(
        public ?string $issuer,
        public ?string $audience,
        public ?string $subject,
        public ?string $jwtId,
        public int $notBefore,
        public int $expiresAt,
    ) {}

    /**
     * @param array<string, mixed> $claims
     */
    public static function fromArray(array $claims): self
    {
        $issuer = self::optionalString($claims, 'iss');
        $audience = self::optionalString($claims, 'aud');
        $subject = self::optionalString($claims, 'sub');
        $jwtId = self::optionalString($claims, 'jti');

        if (!isset($claims['nbf'], $claims['exp']) || !is_numeric($claims['nbf']) || !is_numeric($claims['exp'])) {
            throw new InvalidClaimException('Claims "nbf" and "exp" must be numeric timestamps.');
        }

        $nbf = (int) $claims['nbf'];
        $exp = (int) $claims['exp'];
        if ($exp <= $nbf) {
            throw new InvalidClaimException('Claim "exp" must be greater than "nbf".');
        }

        return new self($issuer, $audience, $subject, $jwtId, $nbf, $exp);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function optionalString(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || $value === '') {
            throw new InvalidClaimException(sprintf('Claim "%s" must be a non-empty string when provided.', $name));
        }

        return $value;
    }
}
