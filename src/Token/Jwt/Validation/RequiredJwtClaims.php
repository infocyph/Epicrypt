<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

final readonly class RequiredJwtClaims
{
    public function __construct(
        public bool $issuer = false,
        public bool $audience = false,
        public bool $subject = false,
        public bool $jwtId = false,
    ) {}
}
