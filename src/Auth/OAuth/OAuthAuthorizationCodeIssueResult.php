<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthAuthorizationCodeIssueResult
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public AuthorizationCode $code,
        public OAuthAuthorizationRecord $authorization,
        public ?string $state = null,
    ) {}

    /** @return array<string, string> */
    public function responseParameters(): array
    {
        return [
            'code' => $this->token,
            'iss' => $this->code->issuer,
            ...($this->state === null ? [] : ['state' => $this->state]),
        ];
    }
}
