<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class RefreshTokenRotationResult
{
    private function __construct(
        public bool $rotated,
        public RefreshTokenRotationStatus $status,
        #[\SensitiveParameter]
        public ?string $token,
        public ?RefreshTokenGrant $grant,
    ) {}

    public static function failure(RefreshTokenRotationStatus $status): self
    {
        return new self(false, $status, null, null);
    }

    public static function success(#[\SensitiveParameter] string $token, RefreshTokenGrant $grant): self
    {
        return new self(true, RefreshTokenRotationStatus::ROTATED, $token, $grant);
    }
}
