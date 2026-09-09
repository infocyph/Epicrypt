<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

interface OpenIdSubjectIdentifierProviderInterface
{
    /**
     * Resolve an application principal to the OIDC subject exposed to one client.
     *
     * Implementations may use public or pairwise subject identifiers. Epicrypt
     * validates the returned identifier before issuing or projecting it.
     */
    public function subject(string $principalId, string $clientId): string;
}
