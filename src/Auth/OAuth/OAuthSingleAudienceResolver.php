<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthSingleAudienceResolver implements OAuthScopeAudienceResolverInterface, OAuthAuthorizationAudienceResolverInterface
{
    public function resolve(OAuthClient $client, array $scopes): array
    {
        if (array_any($scopes, fn(string $scope): bool => !$client->allowsScope($scope))) {
            return [];
        }

        return count($client->audiences) === 1 ? [$client->audiences[0]] : [];
    }
}
