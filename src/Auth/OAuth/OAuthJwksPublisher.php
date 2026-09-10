<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;

final readonly class OAuthJwksPublisher
{
    public function __construct(private AsymmetricSigningKeySet $keys)
    {
        if ($this->keys->purpose !== KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING) {
            throw new ConfigurationException('OAuth JWKS publication requires OAuth access-token signing keys.');
        }
    }

    /** @return array{keys:list<array<string,mixed>>} */
    public function document(): array
    {
        return $this->keys->jwks();
    }
}
