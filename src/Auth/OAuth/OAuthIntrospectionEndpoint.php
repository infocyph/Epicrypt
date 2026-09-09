<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;

/** Transport-neutral RFC 7662 introspection core. */
final readonly class OAuthIntrospectionEndpoint
{
    private OAuthAccessTokenInspector $accessInspector;

    public function __construct(
        OAuthAccessTokenService $accessTokens,
        private RefreshTokenManager $refreshTokens,
    ) {
        $this->accessInspector = new OAuthAccessTokenInspector($accessTokens);
    }

    public function introspect(
        OAuthClientAuthenticationResult $authentication,
        #[\SensitiveParameter]
        string $token,
        ?OAuthTokenTypeHint $hint = null,
    ): OAuthIntrospectionResult {
        $client = $authentication->authenticated ? $authentication->client : null;
        if (!$client instanceof OAuthClient || $client->type !== OAuthClientType::CONFIDENTIAL || !$client->enabled) {
            return OAuthIntrospectionResult::failure(OAuthErrorCode::INVALID_CLIENT);
        }
        if ($token === '' || strlen($token) > AuthProtocolPolicy::MAX_COMPACT_TOKEN_BYTES) {
            return OAuthIntrospectionResult::failure(OAuthErrorCode::INVALID_REQUEST);
        }

        foreach ($this->inspectionOrder($hint) as $type) {
            $response = $type === OAuthTokenTypeHint::ACCESS_TOKEN
                ? $this->inspectAccess($token)
                : $this->inspectRefresh($token);
            if ($response->active) {
                return OAuthIntrospectionResult::success($response);
            }
        }

        return OAuthIntrospectionResult::success(OAuthIntrospectionResponse::inactive());
    }

    private function inspectAccess(#[\SensitiveParameter] string $token): OAuthIntrospectionResponse
    {
        $result = $this->accessInspector->inspect($token);
        if (!$result->valid()) {
            return OAuthIntrospectionResponse::inactive();
        }

        $claims = $result->claims;
        $metadata = [
            'scope' => $claims['scope'] ?? '',
            'client_id' => $claims['client_id'],
            'token_type' => isset($claims['cnf']) ? OAuthAccessTokenType::DPOP->value : OAuthAccessTokenType::BEARER->value,
            'sub' => $claims['sub'],
            'aud' => $claims['aud'],
            'exp' => $claims['exp'],
            'iat' => $claims['iat'],
            'jti' => $claims['jti'],
            'iss' => $claims['iss'],
        ];
        if (isset($claims['nbf'])) {
            $metadata['nbf'] = $claims['nbf'];
        }
        if (isset($claims['cnf'])) {
            $metadata['cnf'] = $claims['cnf'];
        }

        return OAuthIntrospectionResponse::active($metadata);
    }

    /** @return array{OAuthTokenTypeHint, OAuthTokenTypeHint} */
    private function inspectionOrder(?OAuthTokenTypeHint $hint): array
    {
        return match ($hint) {
            OAuthTokenTypeHint::ACCESS_TOKEN => [OAuthTokenTypeHint::ACCESS_TOKEN, OAuthTokenTypeHint::REFRESH_TOKEN],
            OAuthTokenTypeHint::REFRESH_TOKEN => [OAuthTokenTypeHint::REFRESH_TOKEN, OAuthTokenTypeHint::ACCESS_TOKEN],
            null => [OAuthTokenTypeHint::ACCESS_TOKEN, OAuthTokenTypeHint::REFRESH_TOKEN],
        };
    }

    private function inspectRefresh(#[\SensitiveParameter] string $token): OAuthIntrospectionResponse
    {
        $inspection = $this->refreshTokens->inspect($token);
        $record = $inspection->record;
        if (!$inspection->active() || !$record instanceof RefreshTokenRecord) {
            return OAuthIntrospectionResponse::inactive();
        }

        $grant = $record->grant;
        $metadata = [
            'scope' => implode(' ', $grant->scopes),
            'client_id' => $grant->clientId,
            'token_type' => OAuthTokenTypeHint::REFRESH_TOKEN->value,
            'sub' => $grant->subject,
            'aud' => $grant->audiences,
            'exp' => $grant->expiresAt,
            'iat' => $record->issuedAt,
            'jti' => $record->tokenId,
            'authorization_id' => $grant->authorizationId,
        ];
        if ($grant->dpopKeyThumbprint !== null) {
            $metadata['cnf'] = ['jkt' => $grant->dpopKeyThumbprint];
        }

        return OAuthIntrospectionResponse::active($metadata);
    }
}
