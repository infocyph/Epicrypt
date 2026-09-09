<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthTokenResult
{
    private function __construct(
        public ?OAuthTokenResponse $response,
        public ?OAuthProtocolError $error,
    ) {}

    public static function failure(OAuthErrorCode $error): self
    {
        return new self(null, new OAuthProtocolError($error));
    }

    public static function success(OAuthTokenResponse $response): self
    {
        return new self($response, null);
    }

    public function successful(): bool
    {
        return $this->response !== null;
    }
}
