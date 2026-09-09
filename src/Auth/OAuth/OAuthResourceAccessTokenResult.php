<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthResourceAccessTokenResult
{
    private function __construct(
        public OAuthResourceAccessTokenStatus $status,
        public OAuthAccessTokenValidationResult $accessToken,
        public ?OAuthDpopContext $dpop,
    ) {}

    public static function failure(
        OAuthResourceAccessTokenStatus $status,
        OAuthAccessTokenValidationResult $accessToken,
    ): self {
        return new self($status, $accessToken, null);
    }

    public static function success(
        OAuthAccessTokenValidationResult $accessToken,
        ?OAuthDpopContext $dpop = null,
    ): self {
        return new self(OAuthResourceAccessTokenStatus::VALID, $accessToken, $dpop);
    }

    public function valid(): bool
    {
        return $this->status === OAuthResourceAccessTokenStatus::VALID;
    }

    public function tokenType(): string
    {
        return $this->dpop === null ? 'Bearer' : 'DPoP';
    }
}
