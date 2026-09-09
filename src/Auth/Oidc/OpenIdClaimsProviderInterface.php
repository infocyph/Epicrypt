<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

interface OpenIdClaimsProviderInterface
{
    /**
     * Return application-owned UserInfo claims already authorized for the supplied
     * OIDC scopes. The `sub` claim is owned by Epicrypt and must not be returned.
     *
     * @param list<string> $scopes
     * @return array<string, mixed>
     */
    public function claims(string $principalId, string $clientId, array $scopes): array;
}
