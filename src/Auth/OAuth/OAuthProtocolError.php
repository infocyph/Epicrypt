<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthProtocolError
{
    public function __construct(
        public OAuthErrorCode $code,
        public ?string $redirectUri = null,
        public ?string $state = null,
    ) {}

    public function mayRedirect(): bool
    {
        return $this->redirectUri !== null;
    }
}
