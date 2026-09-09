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

    public function __construct(private OAuthClientStoreInterface $clients) {}

    /**
     * Transport-neutral parameter input.
     *
     * A scalar is one occurrence. A list preserves repeated occurrences so
     * Epicrypt can reject duplicate singleton OAuth parameters instead of relying
     * on framework parsing behavior.
     *
     * @param array<string, string|list<string>> $parameters
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
        if ($client === null || !$client->enabled) {
            return $this->reject(OAuthErrorCode::UNAUTHORIZED_CLIENT);
        }

        $redirectUri = $this->resolveRedirectUri($parameters, $client);
        if ($redirectUri === null) {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST);
        }

        $state = $this->safeState($parameters);
        $responseType = $this->singleton($parameters, 'response_type');
        if ($responseType === null || $responseType === '') {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST, $redirectUri, $state);
        }
        if ($responseType !== 'code') {
            return $this->reject(OAuthErrorCode::UNSUPPORTED_RESPONSE_TYPE, $redirectUri, $state);
        }
        if (!$client->allowsGrant(OAuthGrantType::AUTHORIZATION_CODE)) {
            return $this->reject(OAuthErrorCode::UNAUTHORIZED_CLIENT, $redirectUri, $state);
        }

        $challenge = $this->singleton($parameters, 'code_challenge');
        $challengeMethod = $this->singleton($parameters, 'code_challenge_method');
        if ($challenge === null
            || !AuthProtocolPolicy::validSha256Base64Url($challenge)
            || $challengeMethod !== 'S256') {
            return $this->reject(OAuthErrorCode::INVALID_REQUEST, $redirectUri, $state);
        }

        $scopes = $this->resolveScopes($parameters);
        if ($scopes === null || array_any($scopes, static fn(string $scope): bool => !$client->allowsScope($scope))) {
            return $this->reject(OAuthErrorCode::INVALID_SCOPE, $redirectUri, $state);
        }

        return OAuthAuthorizationResult::accepted(
            new OAuthAuthorizationRequest($clientId, $redirectUri, $scopes, $challenge, $state),
            $client,
        );
    }

    /** @param array<string, string|list<string>> $parameters */
    private function validParameterEnvelope(array $parameters): bool
    {
        if (count($parameters) > AuthProtocolPolicy::MAX_PARAMETERS) {
            return false;
        }

        $occurrences = 0;
        foreach ($parameters as $name => $value) {
            if (!AuthProtocolPolicy::validParameterName($name)) {
                return false;
            }
            if (is_string($value)) {
                $occurrences++;
                if ($occurrences > AuthProtocolPolicy::MAX_PARAMETERS
                    || !AuthProtocolPolicy::validParameterValue($value)) {
                    return false;
                }

                continue;
            }
            if (!array_is_list($value) || $value === [] || count($value) > AuthProtocolPolicy::MAX_PARAMETERS) {
                return false;
            }
            $occurrences += count($value);
            if ($occurrences > AuthProtocolPolicy::MAX_PARAMETERS) {
                return false;
            }
            foreach ($value as $item) {
                if (!is_string($item) || !AuthProtocolPolicy::validParameterValue($item)) {
                    return false;
                }
            }
            if (in_array($name, self::SINGLETON_PARAMETERS, true)) {
                return false;
            }
        }

        return true;
    }

    /** @param array<string, string|list<string>> $parameters */
    private function singleton(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    /** @param array<string, string|list<string>> $parameters */
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

    /** @param array<string, string|list<string>> $parameters */
    private function safeState(array $parameters): ?string
    {
        $state = $this->singleton($parameters, 'state');
        if ($state === null || $state === '') {
            return null;
        }

        return AuthProtocolPolicy::validParameterValue($state) ? $state : null;
    }

    /**
     * @param array<string, string|list<string>> $parameters
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

    private function reject(
        OAuthErrorCode $code,
        ?string $redirectUri = null,
        ?string $state = null,
    ): OAuthAuthorizationResult {
        return OAuthAuthorizationResult::rejected(new OAuthProtocolError($code, $redirectUri, $state));
    }
}
