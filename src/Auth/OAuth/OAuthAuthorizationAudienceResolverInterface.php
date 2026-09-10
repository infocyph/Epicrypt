<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

interface OAuthAuthorizationAudienceResolverInterface
{
    /**
     * Resolve validated requested scopes to resource audiences for this client.
     *
     * The application owns scope-to-resource policy. Epicrypt validates the
     * returned audience list against protocol bounds and client registration.
     *
     * @param list<string> $scopes
     * @return list<string>
     */
    public function resolve(OAuthClient $client, array $scopes): array;
}
