<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthRevocationResult
{
    private function __construct(
        public bool $accepted,
        public ?OAuthErrorCode $error,
    ) {}

    public static function failure(OAuthErrorCode $error): self
    {
        return new self(false, $error);
    }

    public static function success(): self
    {
        return new self(true, null);
    }
}
