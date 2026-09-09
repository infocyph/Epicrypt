<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationServerMetadata;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;

final readonly class OpenIdProviderMetadata
{
    /** @var list<string> */
    public array $claimsSupported;

    /** @var list<string> */
    public array $scopesSupported;

    /** @var non-empty-list<OpenIdSubjectType> */
    public array $subjectTypes;

    /**
     * @param array<array-key, mixed> $subjectTypes
     * @param array<array-key, mixed> $scopesSupported
     * @param array<array-key, mixed> $claimsSupported
     */
    public function __construct(
        public OAuthAuthorizationServerMetadata $oauth,
        #[\SensitiveParameter]
        private AsymmetricSigningKeySet $idTokenKeys,
        public string $userInfoEndpoint,
        array $subjectTypes = [OpenIdSubjectType::PUBLIC],
        array $scopesSupported = ['openid'],
        array $claimsSupported = ['sub'],
    ) {
        if ($this->idTokenKeys->purpose !== KeyPurpose::OIDC_ID_TOKEN_SIGNING
            || !hash_equals($this->oauth->issuer, $this->idTokenKeys->issuer)) {
            throw new ConfigurationException('OpenID discovery requires issuer-matched OIDC ID-token signing keys.');
        }
        if ($this->oauth->authorizationEndpoint === null
            || $this->oauth->tokenEndpoint === null
            || $this->oauth->jwksUri === null) {
            throw new ConfigurationException('OpenID discovery requires authorization, token, and JWKS endpoints.');
        }
        if (!self::validHttpsUri($this->userInfoEndpoint)) {
            throw new ConfigurationException('OpenID UserInfo endpoint must be an absolute HTTPS URI.');
        }

        $this->subjectTypes = self::normalizeSubjectTypes($subjectTypes);
        $this->scopesSupported = AuthProtocolPolicy::normalizeScopes($scopesSupported, 'OpenID discovery scopes');
        if (!in_array('openid', $this->scopesSupported, true)) {
            throw new ConfigurationException('OpenID discovery scopes must include openid.');
        }
        $this->claimsSupported = self::normalizeClaims($claimsSupported);
        if (!in_array('sub', $this->claimsSupported, true)) {
            throw new ConfigurationException('OpenID discovery claims must include sub.');
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->oauth->toArray() + [
            'userinfo_endpoint' => $this->userInfoEndpoint,
            'subject_types_supported' => array_map(
                static fn(OpenIdSubjectType $type): string => $type->value,
                $this->subjectTypes,
            ),
            'id_token_signing_alg_values_supported' => [$this->idTokenKeys->algorithm->value],
            'scopes_supported' => $this->scopesSupported,
            'claims_supported' => $this->claimsSupported,
        ];
    }

    /** @param array<array-key, mixed> $claims @return list<string> */
    private static function normalizeClaims(array $claims): array
    {
        if (!array_is_list($claims) || count($claims) > AuthProtocolPolicy::MAX_AUTH_CLAIMS) {
            throw new ConfigurationException('OpenID discovery claims must be a bounded list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($claims as $claim) {
            if (!is_string($claim)
                || !AuthProtocolPolicy::validText($claim, AuthProtocolPolicy::MAX_PARAMETER_NAME_BYTES)
                || isset($seen[$claim])) {
                throw new ConfigurationException('OpenID discovery claims must contain unique bounded names.');
            }
            $seen[$claim] = true;
            $normalized[] = $claim;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $types
     * @return non-empty-list<OpenIdSubjectType>
     */
    private static function normalizeSubjectTypes(array $types): array
    {
        if ($types === [] || !array_is_list($types) || count($types) > count(OpenIdSubjectType::cases())) {
            throw new ConfigurationException('OpenID subject types must be a bounded non-empty list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($types as $type) {
            if (!$type instanceof OpenIdSubjectType || isset($seen[$type->value])) {
                throw new ConfigurationException('OpenID subject types must contain unique typed values.');
            }
            $seen[$type->value] = true;
            $normalized[] = $type;
        }

        /** @var non-empty-list<OpenIdSubjectType> $normalized */
        return $normalized;
    }

    private static function validHttpsUri(string $uri): bool
    {
        $parts = parse_url($uri);

        return is_array($parts)
            && strtolower((string) ($parts['scheme'] ?? '')) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && !isset($parts['user'])
            && !isset($parts['pass'])
            && !isset($parts['fragment']);
    }
}
