<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Token\Jwt\JwtClaims;

final readonly class OAuthAccessTokenIssue
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public JwtClaims $claims,
    ) {}

    public function expiresIn(int $now): int
    {
        return max(0, $this->claims->expiresAt - $now);
    }
}
