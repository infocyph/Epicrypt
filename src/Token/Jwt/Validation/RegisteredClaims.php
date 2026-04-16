<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final readonly class RegisteredClaims
{
    public function __construct(
        public string $issuer,
        public string $audience,
        public string $subject,
        public ?string $jwtId = null,
    ) {}

    /**
     * @param array<string, mixed> $claims
     */
    public static function fromArray(array $claims): self
    {
        $issuer = self::requireStringClaim($claims, 'iss');
        $audience = self::requireStringClaim($claims, 'aud');
        $subject = self::requireStringClaim($claims, 'sub');

        $jwtId = $claims['jti'] ?? null;
        if ($jwtId !== null && (!is_string($jwtId) || $jwtId === '')) {
            throw new InvalidClaimException('Claim "jti" must be a non-empty string when provided.');
        }

        return new self(
            issuer: $issuer,
            audience: $audience,
            subject: $subject,
            jwtId: $jwtId,
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function requireStringClaim(array $claims, string $name): string
    {
        $value = $claims[$name] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidClaimException("Missing or invalid required claim: {$name}");
        }

        return $value;
    }
}
