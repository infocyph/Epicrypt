<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthClient
{
    private const int MAX_REDIRECT_URIS = 32;

    /** @var list<string> */
    public array $redirectUris;

    /** @var non-empty-list<OAuthGrantType> */
    public array $grantTypes;

    /** @var list<string> */
    public array $scopes;

    /** @var list<string> */
    public array $audiences;

    /** @var non-empty-list<OAuthClientAuthenticationMethod> */
    public array $authenticationMethods;

    /**
     * @param array<array-key, mixed> $redirectUris
     * @param array<array-key, mixed> $grantTypes
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $authenticationMethods
     */
    public function __construct(
        public string $clientId,
        public OAuthClientType $type,
        public bool $enabled,
        array $redirectUris,
        array $grantTypes,
        array $scopes,
        array $audiences,
        array $authenticationMethods,
        public ?OAuthClientSecret $secret = null,
        public ?OAuthClientKeySet $assertionKeys = null,
    ) {
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth client ID');
        $this->redirectUris = self::normalizeRedirectUris($redirectUris);
        $this->grantTypes = self::normalizeGrantTypes($grantTypes);
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth client scopes');
        $this->audiences = $audiences === []
            ? []
            : AuthProtocolPolicy::normalizeAudiences($audiences, 'OAuth client audiences');
        $this->authenticationMethods = self::normalizeAuthenticationMethods($authenticationMethods);

        $this->assertGrantProfile();
        $this->assertAuthenticationProfile();
    }

    public function allowsRedirectUri(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->redirectUris, true);
    }

    public function allowsGrant(OAuthGrantType $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    public function allowsScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function allowsAudience(string $audience): bool
    {
        return in_array($audience, $this->audiences, true);
    }

    public function allowsAuthenticationMethod(OAuthClientAuthenticationMethod $method): bool
    {
        return in_array($method, $this->authenticationMethods, true);
    }

    public function verifySecret(#[\SensitiveParameter] string $secret): bool
    {
        return $this->secret?->verify($secret) ?? false;
    }

    private function assertGrantProfile(): void
    {
        if ($this->allowsGrant(OAuthGrantType::AUTHORIZATION_CODE) && $this->redirectUris === []) {
            throw new ConfigurationException('Authorization-code clients require at least one exact redirect URI.');
        }
        if ($this->allowsGrant(OAuthGrantType::REFRESH_TOKEN)
            && !$this->allowsGrant(OAuthGrantType::AUTHORIZATION_CODE)) {
            throw new ConfigurationException('Epicrypt 3 refresh-token clients must also allow authorization_code.');
        }
        if ($this->type === OAuthClientType::PUBLIC && $this->allowsGrant(OAuthGrantType::CLIENT_CREDENTIALS)) {
            throw new ConfigurationException('Public OAuth clients cannot use the client_credentials grant.');
        }
    }

    private function assertAuthenticationProfile(): void
    {
        $usesNone = $this->allowsAuthenticationMethod(OAuthClientAuthenticationMethod::NONE);
        $usesSecret = array_any(
            $this->authenticationMethods,
            static fn(OAuthClientAuthenticationMethod $method): bool => $method->usesClientSecret(),
        );
        $usesPrivateKeyJwt = $this->allowsAuthenticationMethod(OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT);

        if ($this->type === OAuthClientType::PUBLIC) {
            if ($this->authenticationMethods !== [OAuthClientAuthenticationMethod::NONE]
                || $this->secret !== null
                || $this->assertionKeys !== null) {
                throw new ConfigurationException('Public OAuth clients must use only the none authentication method and carry no credentials.');
            }

            return;
        }

        if ($usesNone) {
            throw new ConfigurationException('Confidential OAuth clients cannot use the none authentication method.');
        }
        if ($usesSecret !== ($this->secret !== null)) {
            throw new ConfigurationException('OAuth client-secret configuration must exactly match the enabled secret authentication methods.');
        }
        if ($usesPrivateKeyJwt !== ($this->assertionKeys !== null)) {
            throw new ConfigurationException('OAuth private_key_jwt configuration must exactly match the registered assertion key set.');
        }
    }

    /**
     * @param array<array-key, mixed> $redirectUris
     * @return list<string>
     */
    private static function normalizeRedirectUris(array $redirectUris): array
    {
        if (!array_is_list($redirectUris) || count($redirectUris) > self::MAX_REDIRECT_URIS) {
            throw new ConfigurationException('OAuth client redirect URIs must be a bounded list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($redirectUris as $redirectUri) {
            if (!is_string($redirectUri)
                || !self::validRedirectUri($redirectUri)
                || isset($seen[$redirectUri])) {
                throw new ConfigurationException('OAuth client redirect URIs must contain unique bounded absolute URIs without fragments.');
            }
            $seen[$redirectUri] = true;
            $normalized[] = $redirectUri;
        }

        return $normalized;
    }

    private static function validRedirectUri(string $redirectUri): bool
    {
        if (!AuthProtocolPolicy::validText($redirectUri, AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES)) {
            return false;
        }
        $parts = parse_url($redirectUri);
        if (!is_array($parts)
            || !is_string($parts['scheme'] ?? null)
            || $parts['scheme'] === ''
            || isset($parts['fragment'], $parts['user'], $parts['pass'])) {
            return false;
        }
        $scheme = strtolower($parts['scheme']);

        return !in_array($scheme, ['http', 'https'], true)
            || (is_string($parts['host'] ?? null) && $parts['host'] !== '');
    }

    /**
     * @param array<array-key, mixed> $grantTypes
     * @return non-empty-list<OAuthGrantType>
     */
    private static function normalizeGrantTypes(array $grantTypes): array
    {
        if ($grantTypes === [] || !array_is_list($grantTypes) || count($grantTypes) > count(OAuthGrantType::cases())) {
            throw new ConfigurationException('OAuth client grant types must be a bounded non-empty list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($grantTypes as $grantType) {
            if (!$grantType instanceof OAuthGrantType || isset($seen[$grantType->value])) {
                throw new ConfigurationException('OAuth client grant types must contain unique OAuthGrantType values.');
            }
            $seen[$grantType->value] = true;
            $normalized[] = $grantType;
        }

        /** @var non-empty-list<OAuthGrantType> $normalized */
        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $methods
     * @return non-empty-list<OAuthClientAuthenticationMethod>
     */
    private static function normalizeAuthenticationMethods(array $methods): array
    {
        if ($methods === [] || !array_is_list($methods) || count($methods) > count(OAuthClientAuthenticationMethod::cases())) {
            throw new ConfigurationException('OAuth client authentication methods must be a bounded non-empty list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($methods as $method) {
            if (!$method instanceof OAuthClientAuthenticationMethod || isset($seen[$method->value])) {
                throw new ConfigurationException('OAuth client authentication methods must contain unique typed values.');
            }
            $seen[$method->value] = true;
            $normalized[] = $method;
        }

        /** @var non-empty-list<OAuthClientAuthenticationMethod> $normalized */
        return $normalized;
    }
}
