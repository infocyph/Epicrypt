<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class OAuthTokenEndpoint
{
    public function __construct(
        private OAuthClientStoreInterface $clients,
        private OAuthAccessTokenService $accessTokens,
        private OAuthAuthorizationCodeConsumer $authorizationCodes,
        private RefreshTokenManager $refreshTokens,
        private OAuthAuthorizationStoreInterface $authorizations,
        private OAuthScopeAudienceResolverInterface $audienceResolver = new OAuthSingleAudienceResolver(),
        private ?OAuthDpopValidator $dpop = null,
        private ?string $tokenEndpointUri = null,
        private ClockInterface $clock = new SystemClock(),
        private ?OAuthAuthorizationCodeTokenExtensionInterface $authorizationCodeExtension = null,
    ) {
        if ($this->dpop !== null && ($this->tokenEndpointUri === null || !self::validEndpointUri($this->tokenEndpointUri))) {
            throw new ConfigurationException('OAuth DPoP token endpoint URI must be an absolute HTTPS URI without credentials or fragment.');
        }
    }

    public function authorizationCode(
        string $clientId,
        ?OAuthClientAuthenticationResult $authentication,
        #[\SensitiveParameter]
        string $code,
        string $redirectUri,
        #[\SensitiveParameter]
        string $pkceVerifier,
        #[\SensitiveParameter]
        ?string $dpopProof = null,
    ): OAuthTokenResult {
        $client = $this->resolveClient($clientId, $authentication, OAuthGrantType::AUTHORIZATION_CODE);
        if ($client instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($client);
        }
        $dpop = $this->resolveDpop($dpopProof);
        if ($dpop instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($dpop);
        }

        $consumed = $this->authorizationCodes->consume($code, $clientId, $redirectUri, $pkceVerifier);
        if (!$consumed->consumed || $consumed->code === null || $consumed->authorization === null) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }

        try {
            $refreshToken = $this->issueRefreshToken($client, $consumed, $dpop);
            $access = $this->accessTokens->issue(
                subject: $consumed->code->subject,
                clientId: $clientId,
                audiences: $consumed->code->audiences,
                scopes: $consumed->code->scopes,
                authorizationId: $consumed->authorization->authorizationId,
                dpopKeyThumbprint: $dpop?->keyThumbprint,
            );
            $additionalParameters = $this->authorizationCodeExtension?->parameters(
                $consumed->code,
                $access,
                $code,
            ) ?? [];
        } catch (Throwable) {
            $this->failClosedAuthorization($consumed->authorization->authorizationId);

            return OAuthTokenResult::failure(OAuthErrorCode::SERVER_ERROR);
        }

        return OAuthTokenResult::success($this->response(
            $access,
            $consumed->code->scopes,
            $refreshToken,
            $dpop,
            $additionalParameters,
        ));
    }

    /** @param null|array<array-key, mixed> $requestedScopes */
    public function clientCredentials(
        OAuthClientAuthenticationResult $authentication,
        ?array $requestedScopes = null,
        #[\SensitiveParameter]
        ?string $dpopProof = null,
    ): OAuthTokenResult {
        $authenticatedClient = $authentication->authenticated ? $authentication->client : null;
        if (!$authenticatedClient instanceof OAuthClient) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_CLIENT);
        }
        $client = $this->resolveClient(
            $authenticatedClient->clientId,
            $authentication,
            OAuthGrantType::CLIENT_CREDENTIALS,
            requireConfidential: true,
        );
        if ($client instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($client);
        }

        $dpop = $this->resolveDpop($dpopProof);
        if ($dpop instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($dpop);
        }
        $resolved = $this->resolveScopesAndAudiences($client, $requestedScopes ?? $client->scopes);
        if ($resolved instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($resolved);
        }
        if (in_array('openid', $resolved['scopes'], true)) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_SCOPE);
        }

        try {
            $access = $this->accessTokens->issue(
                subject: $client->clientId,
                clientId: $client->clientId,
                audiences: $resolved['audiences'],
                scopes: $resolved['scopes'],
                dpopKeyThumbprint: $dpop?->keyThumbprint,
            );
        } catch (Throwable) {
            return OAuthTokenResult::failure(OAuthErrorCode::SERVER_ERROR);
        }

        return OAuthTokenResult::success($this->response($access, $resolved['scopes'], null, $dpop));
    }

    /** @param null|array<array-key, mixed> $requestedScopes */
    public function refreshToken(
        string $clientId,
        ?OAuthClientAuthenticationResult $authentication,
        #[\SensitiveParameter]
        string $refreshToken,
        ?array $requestedScopes = null,
        #[\SensitiveParameter]
        ?string $dpopProof = null,
    ): OAuthTokenResult {
        $client = $this->resolveClient($clientId, $authentication, OAuthGrantType::REFRESH_TOKEN);
        if ($client instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($client);
        }
        $dpop = $this->resolveDpop($dpopProof);
        if ($dpop instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($dpop);
        }

        $inspection = $this->refreshTokens->inspect($refreshToken);
        $grant = $inspection->grant();
        if (!$grant instanceof RefreshTokenGrant || !hash_equals($grant->clientId, $clientId)) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }
        $actualDpop = $dpop?->keyThumbprint;
        if ($grant->dpopKeyThumbprint !== $actualDpop) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_DPOP_PROOF);
        }
        if ($inspection->status === RefreshTokenInspectionStatus::CONSUMED) {
            $this->refreshTokens->rotate($refreshToken, $clientId, $actualDpop);

            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }
        if (!$inspection->active()) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }

        $authorization = $this->authorizations->find($grant->authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($this->clock->now()->getTimestamp())
            || !$authorization->matchesRefreshGrant($grant)) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }

        $scopes = $this->refreshScopes($client, $grant, $requestedScopes);
        if ($scopes instanceof OAuthErrorCode) {
            return OAuthTokenResult::failure($scopes);
        }

        $rotation = $this->refreshTokens->rotate(
            $refreshToken,
            $clientId,
            $actualDpop,
            requestedScopes: $scopes,
        );
        if (!$rotation->rotated || $rotation->token === null || $rotation->grant === null) {
            return OAuthTokenResult::failure(
                $rotation->status === RefreshTokenRotationStatus::SCOPE_MISMATCH
                    ? OAuthErrorCode::INVALID_SCOPE
                    : OAuthErrorCode::INVALID_GRANT,
            );
        }

        try {
            $access = $this->accessTokens->issue(
                subject: $rotation->grant->subject,
                clientId: $clientId,
                audiences: $rotation->grant->audiences,
                scopes: $rotation->grant->scopes,
                authorizationId: $rotation->grant->authorizationId,
                dpopKeyThumbprint: $actualDpop,
            );
        } catch (Throwable) {
            $this->failClosedAuthorization($rotation->grant->authorizationId);

            return OAuthTokenResult::failure(OAuthErrorCode::SERVER_ERROR);
        }

        return OAuthTokenResult::success($this->response($access, $rotation->grant->scopes, $rotation->token, $dpop));
    }

    private function issueRefreshToken(
        OAuthClient $client,
        OAuthAuthorizationCodeConsumeResult $consumed,
        ?OAuthDpopContext $dpop,
    ): ?string {
        if (!$client->allowsGrant(OAuthGrantType::REFRESH_TOKEN)
            || $consumed->code === null
            || $consumed->authorization === null) {
            return null;
        }

        return $this->refreshTokens->issue(new RefreshTokenGrant(
            authorizationId: $consumed->authorization->authorizationId,
            subject: $consumed->code->subject,
            clientId: $client->clientId,
            audiences: $consumed->code->audiences,
            scopes: $consumed->code->scopes,
            expiresAt: $consumed->authorization->expiresAt,
            dpopKeyThumbprint: $dpop?->keyThumbprint,
        ));
    }

    /**
     * @param null|array<array-key, mixed> $requestedScopes
     * @return list<string>|OAuthErrorCode
     */
    private function refreshScopes(
        OAuthClient $client,
        RefreshTokenGrant $grant,
        ?array $requestedScopes,
    ): array|OAuthErrorCode {
        try {
            $scopes = AuthProtocolPolicy::normalizeScopes(
                $requestedScopes ?? $grant->scopes,
                'OAuth refresh requested scopes',
            );
        } catch (Throwable) {
            return OAuthErrorCode::INVALID_SCOPE;
        }

        return array_any(
            $scopes,
            static fn(string $scope): bool => !$client->allowsScope($scope) || !in_array($scope, $grant->scopes, true),
        ) ? OAuthErrorCode::INVALID_SCOPE : $scopes;
    }

    private function failClosedAuthorization(string $authorizationId): void
    {
        $now = $this->clock->now()->getTimestamp();
        $this->authorizations->revoke($authorizationId, $now);
        $this->refreshTokens->revokeAuthorization($authorizationId);
    }

    private function resolveClient(
        string $clientId,
        ?OAuthClientAuthenticationResult $authentication,
        OAuthGrantType $grantType,
        bool $requireConfidential = false,
    ): OAuthClient|OAuthErrorCode {
        if (!AuthProtocolPolicy::validText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)) {
            return OAuthErrorCode::INVALID_CLIENT;
        }
        $client = $this->clients->find($clientId);
        if (!$client instanceof OAuthClient || !$client->enabled) {
            return OAuthErrorCode::INVALID_CLIENT;
        }
        if (!$client->allowsGrant($grantType)) {
            return OAuthErrorCode::UNAUTHORIZED_CLIENT;
        }
        if ($requireConfidential && $client->type !== OAuthClientType::CONFIDENTIAL) {
            return OAuthErrorCode::INVALID_CLIENT;
        }
        if (!$this->validAuthenticationForClient($client, $authentication)) {
            return OAuthErrorCode::INVALID_CLIENT;
        }

        return $client;
    }

    private function validAuthenticationForClient(
        OAuthClient $client,
        ?OAuthClientAuthenticationResult $authentication,
    ): bool {
        if ($client->type === OAuthClientType::CONFIDENTIAL) {
            return $authentication !== null
                && $authentication->authenticated
                && $authentication->client instanceof OAuthClient
                && hash_equals($client->clientId, $authentication->client->clientId);
        }
        if ($authentication === null) {
            return true;
        }

        return $authentication->authenticated
            && $authentication->client instanceof OAuthClient
            && hash_equals($client->clientId, $authentication->client->clientId);
    }

    /**
     * @param array<array-key, mixed> $requestedScopes
     * @return array{scopes:list<string>,audiences:list<string>}|OAuthErrorCode
     */
    private function resolveScopesAndAudiences(OAuthClient $client, array $requestedScopes): array|OAuthErrorCode
    {
        try {
            $scopes = AuthProtocolPolicy::normalizeScopes($requestedScopes, 'OAuth token requested scopes');
        } catch (Throwable) {
            return OAuthErrorCode::INVALID_SCOPE;
        }
        if (array_any($scopes, static fn(string $scope): bool => !$client->allowsScope($scope))) {
            return OAuthErrorCode::INVALID_SCOPE;
        }

        try {
            $resolved = $this->audienceResolver->resolve($client, $scopes);
        } catch (Throwable) {
            return OAuthErrorCode::SERVER_ERROR;
        }
        try {
            $audiences = AuthProtocolPolicy::normalizeAudiences($resolved, 'OAuth token audiences');
        } catch (Throwable) {
            return OAuthErrorCode::INVALID_SCOPE;
        }
        if (array_any($audiences, static fn(string $audience): bool => !$client->allowsAudience($audience))) {
            return OAuthErrorCode::INVALID_SCOPE;
        }

        return ['scopes' => $scopes, 'audiences' => $audiences];
    }

    private function resolveDpop(#[\SensitiveParameter] ?string $proof): OAuthDpopContext|OAuthErrorCode|null
    {
        if ($proof === null) {
            return null;
        }
        if ($this->dpop === null || $this->tokenEndpointUri === null) {
            return OAuthErrorCode::INVALID_DPOP_PROOF;
        }
        try {
            return $this->dpop->validateTokenEndpoint($proof, $this->tokenEndpointUri);
        } catch (InvalidTokenException) {
            return OAuthErrorCode::INVALID_DPOP_PROOF;
        } catch (Throwable) {
            return OAuthErrorCode::SERVER_ERROR;
        }
    }

    /**
     * @param list<string> $scopes
     * @param array<string, string> $additionalParameters
     */
    private function response(
        OAuthAccessTokenIssue $access,
        array $scopes,
        ?string $refreshToken,
        ?OAuthDpopContext $dpop,
        #[\SensitiveParameter]
        array $additionalParameters = [],
    ): OAuthTokenResponse {
        return new OAuthTokenResponse(
            accessToken: $access->token,
            tokenType: $dpop === null ? OAuthAccessTokenType::BEARER : OAuthAccessTokenType::DPOP,
            expiresIn: max(0, $access->claims->expiresAt - $access->claims->issuedAt),
            scopes: $scopes,
            refreshToken: $refreshToken,
            additionalParameters: $additionalParameters,
        );
    }

    private static function validEndpointUri(string $uri): bool
    {
        $parts = parse_url($uri);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && !isset($parts['user'])
            && !isset($parts['pass'])
            && !isset($parts['fragment']);
    }
}
