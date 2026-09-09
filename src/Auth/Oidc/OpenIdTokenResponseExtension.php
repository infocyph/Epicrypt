<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenIssue;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeTokenExtensionInterface;

final readonly class OpenIdTokenResponseExtension implements OAuthAuthorizationCodeTokenExtensionInterface
{
    public function __construct(#[\SensitiveParameter] private OpenIdIdTokenIssuer $idTokens) {}

    public function parameters(
        AuthorizationCode $code,
        #[\SensitiveParameter]
        OAuthAccessTokenIssue $accessToken,
        #[\SensitiveParameter]
        string $authorizationCode,
    ): array {
        if (!in_array('openid', $code->scopes, true)) {
            return [];
        }

        $idToken = $this->idTokens->issue($code, accessToken: $accessToken->token);

        return ['id_token' => $idToken->token];
    }
}
