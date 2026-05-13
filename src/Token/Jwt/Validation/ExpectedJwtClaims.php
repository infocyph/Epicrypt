<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

final readonly class ExpectedJwtClaims
{
    public function __construct(
        public ?string $issuer = null,
        public ?string $audience = null,
        public ?string $subject = null,
        public ?string $jwtId = null,
        public RequiredJwtClaims $required = new RequiredJwtClaims(),
        public int $leewaySeconds = 0,
        public ?int $maxTokenAgeSeconds = null,
    ) {}

    public static function fromRegistered(RegisteredClaims $claims): self
    {
        return new self(
            issuer: $claims->issuer,
            audience: $claims->audience,
            subject: $claims->subject,
            jwtId: $claims->jwtId,
            required: new RequiredJwtClaims(true, true, true, $claims->jwtId !== null),
        );
    }
}
