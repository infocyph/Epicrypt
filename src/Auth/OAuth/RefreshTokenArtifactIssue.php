<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class RefreshTokenArtifactIssue
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public RefreshTokenArtifactClaims $claims,
    ) {}
}
