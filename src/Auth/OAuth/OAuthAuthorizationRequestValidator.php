<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Throwable;

final readonly class OAuthAuthorizationRequestValidator
{
    private const array SINGLETON_PARAMETERS = [
        'client_id',
        'redirect_uri',
        'response_type',
        'scope',
        'state',
        'code_challenge',
        'code_challenge_method',
    ];

    public function __construct(
        private OAuthClientStoreInterface $clients,
        private OAuthAuthorizationAudienceResolverInterface $audienceResolver = new OAuthSingleAudienceResolver(),
    ) {}

    /**
     * Transport-neutral parameter input.
     *
     * A scalar is one occurrence. A list preserves repeated occurrences so
     * Epicrypt can reject duplicate singleton OAuth parameters instead of relying
     * on framework parsing behavior.
     *
     * @param array<array-key, mixed> $parameters
     */
    public function validate(array $parameters): OAuthAuthorizationResult
    {
        if (!$this->validParameterEnvelope($parameters)) {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST);
        }

        $clientId = $this->singleton($parameters, 'client_id');
        if ($clientId === null || !AuthProtocolPolicy::validText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)) {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST);
        }
        $client = $this->clients->find($clientId);
        if (!$client instanceof OAuthClient || !$client->enabled) {
            return $this->reject(OAuthErrorCode::UNAUTHORIZED_CLIENT);
        }

        $redirectUri = $this->resolveRedirectUri($parameters, $client);
        if ($redirectUri === null) {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST);
        }

        $state = $this->state($parameters);
        if ($state === false) {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST, $redirectUri);
        }

        $profileError = $this->authorizationProfileError($parameters, $client);
        if ($profileError !== null) {
            return $this->reject($profileError, $redirectUri, $state);
        }

        $challenge = $this->singleton($parameters, 'code_challenge');
        $scopes = $this->resolveScopes($parameters);
        if ($challenge === null || $scopes === null || $this->containsUnregisteredScope($client, $scopes)) {
            return $this->reject(OAuthErrorCode::INVALID_SCOPE, $redirectUri, $state);
        }

        $audiences = $this->resolveAudiences($client, $scopes);
        if ($audiences instanceof OAuthErrorCode) {
            return $this->reject($audiences, $redirectUri, $state);
        }

        return OAuthAuthorizationResult::accepted(
            new OAuthAuthorizationRequest($client->clientId, $redirectUri, $scopes, $audiences, $challenge, $state),
            $client,
        );
    }

    /** @param array<array-key, mixed> $parameters */
    private function validParameterEnvelope(array $parameters): bool
    {
        if (count($parameters) > AuthProtocolPolicy::MAX_PARAMETERS) {
            return false;
        }

        $occurrences = 0;
        foreach ($parameters as $name => $value) {
            if (!is_string($name) || !AuthProtocolPolicy::validParameterName($name)) {
                return false;
            }
            $values = $this->parameterValues($value);
            if ($values === null || (is_array($value) && in_array($name, self::SINGLETON_PARAMETERS, true))) {
                return false;
            }
            $occurrences += count($values);
            if ($occurrences > AuthProtocolPolicy::MAX_PARAMETERS
                || array_any($values, static fn(string $item): bool => !AuthProtocolPolicy::validParameterValue($item))) {
                return false;
            }
        }

        return true;
    }

    /** @return list<string>|null */
    private function parameterValues(mixed $value): ?array
    {
        if (is_string($value)) {
            return [$value];
        }
        if (!is_array($value)
            || $value === []
            || !array_is_list($value)
            || count($value) > AuthProtocolPolicy::MAX_PARAMETERS) {
            return null;
        }
        if (array_any($value, static fn(mixed $item): bool => !is_string($item))) {
            return null;
        }

        /** @var list<string> $value */
        return $value;
    }

    /** @param array<array-key, mixed> $parameters */
    private function authorizationProfileError(array $parameters, OAuthClient $client): ?OAuthErrorCode
    {
        $responseType = $this->singleton($parameters, 'response_type');
        if ($responseType === null || $responseType === '') {
            return OAuthErrorCode::INVALID_REQUEST;
        }
        if ($responseType !== 'code') {
            return OAuthErrorCode::UNSUPPORTED_RESPONSE_TYPE;
        }
        if (!$client->allowsGrant(OAuthGrantType::AUTHORIZATION_CODE)) {
            return OAuthErrorCode::UNAUTHORIZED_CLIENT;
        }

        $challenge = $this->singleton($parameters, 'code_challenge');
        $method = $this->singleton($parameters, 'code_challenge_method');

        return $challenge !== null
            && AuthProtocolPolicy::validSha256Base64Url($challenge)
            && $method === 'S256'
            ? null
            : OAuthErrorCode::INVALID_REQUEST;
    }

    /** @param array<array-key, mixed> $parameters */
    private function singleton(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    /** @param array<array-key, mixed> $parameters */
    private function resolveRedirectUri(array $parameters, OAuthClient $client): ?string
    {
        $redirectUri = $this->singleton($parameters, 'redirect_uri');
        if ($redirectUri !== null) {
            return AuthProtocolPolicy::validText($redirectUri, AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES)
                && $client->allowsRedirectUri($redirectUri)
                ? $redirectUri
                : null;
        }

        return count($client->redirectUris) === 1 ? $client->redirectUris[0] : null;
    }

    /** @param array<array-key, mixed> $parameters */
    private function state(array $parameters): string|false|null
    {
        if (!array_key_exists('state', $parameters)) {
            return null;
        }

        $state = $this->singleton($parameters, 'state');

        return $state !== null
            && $state !== ''
            && AuthProtocolPolicy::validParameterValue($state)
            ? $state
            : false;
    }

    /**
     * @param array<array-key, mixed> $parameters
     * @return list<string>|null
     */
    private function resolveScopes(array $parameters): ?array
    {
        $scope = $this->singleton($parameters, 'scope');
        if ($scope === null || $scope === '') {
            return [];
        }

        try {
            return AuthProtocolPolicy::normalizeScopes(explode(' ', $scope), 'OAuth authorization scopes');
        } catch (Throwable) {
            return null;
        }
    }

    /** @param list<string> $scopes */
    private function containsUnregisteredScope(OAuthClient $client, array $scopes): bool
    {
        return array_any($scopes, static fn(string $scope): bool => !$client->allowsScope($scope));
    }

    /**
     * @param list<string> $scopes
     * @return non-empty-list<string>|OAuthErrorCode
     */
    private function resolveAudiences(OAuthClient $client, array $scopes): array|OAuthErrorCode
    {
        try {
            $resolved = $this->audienceResolver->resolve($client, $scopes);
        } catch (Throwable) {
            return OAuthErrorCode::SERVER_ERROR;
        }

        try {
            /** @var non-empty-list<string> $audiences */
            $audiences = AuthProtocolPolicy::normalizeAudiences($resolved, 'OAuth authorization request audiences');
        } catch (Throwable) {
            return OAuthErrorCode::INVALID_REQUEST;
        }

        return array_any($audiences, static fn(string $audience): bool => !$client->allowsAudience($audience))
            ? OAuthErrorCode::INVALID_REQUEST
            : $audiences;
    }

    private function reject(
        OAuthErrorCode $code,
        ?string $redirectUri = null,
        ?string $state = null,
    ): OAuthAuthorizationResult {
        return OAuthAuthorizationResult::rejected(new OAuthProtocolError($code, $redirectUri, $state));
    }
}
