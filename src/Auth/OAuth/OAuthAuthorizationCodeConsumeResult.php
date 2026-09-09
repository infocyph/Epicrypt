<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthAuthorizationCodeConsumeResult
{
    private function __construct(
        public bool $consumed,
        public OAuthAuthorizationCodeConsumeStatus $status,
        public ?AuthorizationCode $code,
        public ?OAuthAuthorizationRecord $authorization,
    ) {}

    public static function success(
        AuthorizationCode $code,
        OAuthAuthorizationRecord $authorization,
    ): self {
        return new self(
            true,
            OAuthAuthorizationCodeConsumeStatus::CONSUMED,
            $code,
            $authorization,
        );
    }

    public static function failure(OAuthAuthorizationCodeConsumeStatus $status): self
    {
        return new self(false, $status, null, null);
    }
}
