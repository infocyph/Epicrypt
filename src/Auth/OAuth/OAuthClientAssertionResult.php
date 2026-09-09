<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthClientAssertionResult
{
    /** @param array<string, mixed> $claims */
    private function __construct(
        public bool $valid,
        public OAuthClientAssertionStatus $status,
        public array $claims,
    ) {}

    /** @param array<string, mixed> $claims */
    public static function success(array $claims): self
    {
        return new self(true, OAuthClientAssertionStatus::VALID, $claims);
    }

    public static function failure(OAuthClientAssertionStatus $status): self
    {
        return new self(false, $status, []);
    }
}
