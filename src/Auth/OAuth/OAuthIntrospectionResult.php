<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthIntrospectionResult
{
    private function __construct(
        public ?OAuthIntrospectionResponse $response,
        public ?OAuthErrorCode $error,
    ) {}

    public static function success(OAuthIntrospectionResponse $response): self
    {
        return new self($response, null);
    }

    public static function failure(OAuthErrorCode $error): self
    {
        return new self(null, $error);
    }
}
