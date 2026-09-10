<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthDpopContext
{
    /** @param array<string, mixed> $publicJwk */
    public function __construct(
        public string $keyThumbprint,
        public array $publicJwk,
    ) {
        if (!AuthProtocolPolicy::validSha256Base64Url($this->keyThumbprint) || $this->publicJwk === []) {
            throw new ConfigurationException('OAuth DPoP context is invalid.');
        }
    }
}
