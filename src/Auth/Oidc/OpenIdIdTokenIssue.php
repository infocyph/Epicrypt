<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Token\Jwt\JwtClaims;

final readonly class OpenIdIdTokenIssue
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public JwtClaims $claims,
    ) {}
}
