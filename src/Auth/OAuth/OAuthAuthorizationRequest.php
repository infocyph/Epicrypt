<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthAuthorizationRequest
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $clientId,
        public string $redirectUri,
        public array $scopes,
        public string $codeChallenge,
        public ?string $state = null,
    ) {}
}
