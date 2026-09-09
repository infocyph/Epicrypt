<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class AuthorizationCodeIssue
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public AuthorizationCode $code,
    ) {}
}
