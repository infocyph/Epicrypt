<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthClientAuthenticationResult
{
    private function __construct(
        public bool $authenticated,
        public ?OAuthClient $client,
        public ?OAuthClientAuthenticationFailureReason $reason,
        public ?OAuthClientAssertionStatus $assertionStatus,
    ) {}

    public static function failure(
        OAuthClientAuthenticationFailureReason $reason,
        ?OAuthClientAssertionStatus $assertionStatus = null,
    ): self {
        return new self(false, null, $reason, $assertionStatus);
    }

    public static function success(OAuthClient $client): self
    {
        return new self(true, $client, null, null);
    }
}
