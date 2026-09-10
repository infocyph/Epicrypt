<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

interface OAuthAuthorizationCodeTokenExtensionInterface
{
    /**
     * Produce additional successful token-response parameters for one completed
     * authorization-code exchange.
     *
     * Implementations must not override OAuthTokenResponse reserved parameters.
     * Throwing fails the authorization closed.
     *
     * @return array<string, string>
     */
    public function parameters(
        AuthorizationCode $code,
        #[\SensitiveParameter]
        OAuthAccessTokenIssue $accessToken,
        #[\SensitiveParameter]
        string $authorizationCode,
    ): array;
}
