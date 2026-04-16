<?php

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
        foreach (['iss', 'aud', 'sub'] as $requiredClaim) {
            if (!isset($claims[$requiredClaim]) || !is_string($claims[$requiredClaim]) || $claims[$requiredClaim] === '') {
                throw new InvalidClaimException("Missing or invalid required claim: {$requiredClaim}");
            }
        }

        $jwtId = $claims['jti'] ?? null;
        if ($jwtId !== null && (!is_string($jwtId) || $jwtId === '')) {
            throw new InvalidClaimException('Claim "jti" must be a non-empty string when provided.');
        }

        return new self(
            issuer: $claims['iss'],
            audience: $claims['aud'],
            subject: $claims['sub'],
            jwtId: $jwtId,
        );
    }
}
