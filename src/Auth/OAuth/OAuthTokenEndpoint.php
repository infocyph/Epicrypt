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
            $refreshToken = null;
            if ($client->allowsGrant(OAuthGrantType::REFRESH_TOKEN)) {
                $refreshToken = $this->refreshTokens->issue(new RefreshTokenGrant(
                    authorizationId: $consumed->authorization->authorizationId,
                    subject: $consumed->code->subject,
                    clientId: $clientId,
                    audiences: $consumed->code->audiences,
                    scopes: $consumed->code->scopes,
                    expiresAt: $consumed->authorization->expiresAt,
                    dpopKeyThumbprint: $dpop?->keyThumbprint,
                ));
            }

            $access = $this->accessTokens->issue(
                subject: $consumed->code->subject,
                clientId: $clientId,
                audiences: $consumed->code->audiences,
                scopes: $consumed->code->scopes,
                authorizationId: $consumed->authorization->authorizationId,
                dpopKeyThumbprint: $dpop?->keyThumbprint,
            );
        } catch (Throwable) {
            return OAuthTokenResult::failure(OAuthErrorCode::SERVER_ERROR);
        }

        return OAuthTokenResult::success($this->response($access, $consumed->code->scopes, $refreshToken, $dpop));
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
        if (!$inspection->active() || !$grant instanceof RefreshTokenGrant || !hash_equals($grant->clientId, $clientId)) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }
        $actualDpop = $dpop?->keyThumbprint;
        if ($grant->dpopKeyThumbprint !== $actualDpop) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_DPOP_PROOF);
        }

        $authorization = $this->authorizations->find($grant->authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($this->clock->now()->getTimestamp())
            || !$authorization->matchesRefreshGrant($grant)) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_GRANT);
        }

        $scopes = $requestedScopes ?? $grant->scopes;
        try {
            $scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth refresh requested scopes');
        } catch (Throwable) {
            return OAuthTokenResult::failure(OAuthErrorCode::INVALID_SCOPE);
        }
        foreach ($scopes as $scope) {
            if (!$client->allowsScope($scope) || !in_array($scope, $grant->scopes, true)) {
                return OAuthTokenResult::failure(OAuthErrorCode::INVALID_SCOPE);
            }
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
            return OAuthTokenResult::failure(OAuthErrorCode::SERVER_ERROR);
        }

        return OAuthTokenResult::success($this->response($access, $rotation->grant->scopes, $rotation->token, $dpop));
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

        if ($client->type === OAuthClientType::CONFIDENTIAL) {
            if ($authentication === null
                || !$authentication->authenticated
                || !$authentication->client instanceof OAuthClient
                || !hash_equals($clientId, $authentication->client->clientId)) {
                return OAuthErrorCode::INVALID_CLIENT;
            }
        } elseif ($authentication !== null) {
            if (!$authentication->authenticated
                || !$authentication->client instanceof OAuthClient
                || !hash_equals($clientId, $authentication->client->clientId)) {
                return OAuthErrorCode::INVALID_CLIENT;
            }
        }

        return $client;
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
        foreach ($scopes as $scope) {
            if (!$client->allowsScope($scope)) {
                return OAuthErrorCode::INVALID_SCOPE;
            }
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
        foreach ($audiences as $audience) {
            if (!$client->allowsAudience($audience)) {
                return OAuthErrorCode::INVALID_SCOPE;
            }
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

    /** @param list<string> $scopes */
    private function response(
        OAuthAccessTokenIssue $access,
        array $scopes,
        ?string $refreshToken,
        ?OAuthDpopContext $dpop,
    ): OAuthTokenResponse {
        return new OAuthTokenResponse(
            accessToken: $access->token,
            tokenType: $dpop === null ? OAuthAccessTokenType::BEARER : OAuthAccessTokenType::DPOP,
            expiresIn: max(0, $access->claims->expiresAt - $access->claims->issuedAt),
            scopes: $scopes,
            refreshToken: $refreshToken,
        );
    }

    private static function validEndpointUri(string $uri): bool
    {
        $parts = parse_url($uri);
        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && !isset($parts['user'], $parts['pass'], $parts['fragment']);
    }
}
