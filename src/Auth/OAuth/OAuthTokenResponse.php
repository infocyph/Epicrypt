<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthTokenResponse
{
    /** @var list<string> */
    public array $scopes;

    /** @param list<string> $scopes */
    public function __construct(
        #[\SensitiveParameter]
        public string $accessToken,
        public OAuthAccessTokenType $tokenType,
        public int $expiresIn,
        array $scopes,
        #[\SensitiveParameter]
        public ?string $refreshToken = null,
    ) {
        $this->scopes = $scopes;
    }

    /** @return array<string, mixed> */
    public function parameters(): array
    {
        return [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType->value,
            'expires_in' => $this->expiresIn,
            ...($this->scopes === [] ? [] : ['scope' => implode(' ', $this->scopes)]),
            ...($this->refreshToken === null ? [] : ['refresh_token' => $this->refreshToken]),
        ];
    }
}
