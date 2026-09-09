<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

/** RFC 8414 metadata projected from explicitly enabled Epicrypt capabilities. */
final readonly class OAuthAuthorizationServerMetadata
{
    /** @var list<AsymmetricJwtAlgorithm> */
    public array $clientAssertionSigningAlgorithms;

    /** @var list<AsymmetricJwtAlgorithm> */
    public array $dpopSigningAlgorithms;

    /**
     * @param array<array-key, mixed> $dpopSigningAlgorithms
     * @param array<array-key, mixed> $clientAssertionSigningAlgorithms
     */
    public function __construct(
        public string $issuer,
        public OAuthEndpointCapabilityCatalog $capabilities,
        public ?string $authorizationEndpoint,
        public ?string $tokenEndpoint,
        public ?string $revocationEndpoint = null,
        public ?string $introspectionEndpoint = null,
        public ?string $jwksUri = null,
        array $dpopSigningAlgorithms = [],
        array $clientAssertionSigningAlgorithms = [],
    ) {
        self::assertIssuer($this->issuer);
        $this->assertEndpoint(OAuthEndpointCapability::AUTHORIZATION, $this->authorizationEndpoint, 'authorization endpoint');
        $this->assertEndpoint(OAuthEndpointCapability::TOKEN, $this->tokenEndpoint, 'token endpoint');
        $this->assertEndpoint(OAuthEndpointCapability::REVOCATION, $this->revocationEndpoint, 'revocation endpoint');
        $this->assertEndpoint(OAuthEndpointCapability::INTROSPECTION, $this->introspectionEndpoint, 'introspection endpoint');
        $this->assertEndpoint(OAuthEndpointCapability::JWKS, $this->jwksUri, 'JWKS URI');
        $this->dpopSigningAlgorithms = self::normalizeAlgorithms($dpopSigningAlgorithms, 'OAuth DPoP signing algorithms');
        $this->clientAssertionSigningAlgorithms = self::normalizeAlgorithms(
            $clientAssertionSigningAlgorithms,
            'OAuth client-assertion signing algorithms',
        );

        if (!$this->capabilities->supportsEndpoint(OAuthEndpointCapability::TOKEN)
            && $this->capabilities->grantTypes !== []) {
            throw new ConfigurationException('OAuth grant capabilities require a token endpoint.');
        }
        if ($this->dpopSigningAlgorithms !== []
            && !$this->capabilities->supportsEndpoint(OAuthEndpointCapability::TOKEN)) {
            throw new ConfigurationException('OAuth DPoP metadata requires a token endpoint capability.');
        }
        if ($this->clientAssertionSigningAlgorithms !== []
            && !$this->capabilities->supportsClientAuthentication(OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT)) {
            throw new ConfigurationException('OAuth client-assertion algorithms require private_key_jwt capability.');
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $metadata = [
            'issuer' => $this->issuer,
            'response_types_supported' => $this->capabilities->responseTypes(),
            'grant_types_supported' => array_map(
                static fn(OAuthGrantType $grant): string => $grant->value,
                $this->capabilities->grantTypes,
            ),
            'token_endpoint_auth_methods_supported' => array_map(
                static fn(OAuthClientAuthenticationMethod $method): string => $method->value,
                $this->capabilities->clientAuthenticationMethods,
            ),
            'code_challenge_methods_supported' => $this->capabilities->codeChallengeMethods(),
            'authorization_response_iss_parameter_supported' => true,
        ];

        foreach ([
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'revocation_endpoint' => $this->revocationEndpoint,
            'introspection_endpoint' => $this->introspectionEndpoint,
            'jwks_uri' => $this->jwksUri,
        ] as $name => $uri) {
            if ($uri !== null) {
                $metadata[$name] = $uri;
            }
        }
        if ($this->revocationEndpoint !== null) {
            $metadata['revocation_endpoint_auth_methods_supported'] = $metadata['token_endpoint_auth_methods_supported'];
        }
        if ($this->introspectionEndpoint !== null) {
            $metadata['introspection_endpoint_auth_methods_supported'] = array_values(array_filter(
                $metadata['token_endpoint_auth_methods_supported'],
                static fn(string $method): bool => $method !== OAuthClientAuthenticationMethod::NONE->value,
            ));
        }
        if ($this->clientAssertionSigningAlgorithms !== []) {
            $algorithms = self::algorithmValues($this->clientAssertionSigningAlgorithms);
            $metadata['token_endpoint_auth_signing_alg_values_supported'] = $algorithms;
            if ($this->revocationEndpoint !== null) {
                $metadata['revocation_endpoint_auth_signing_alg_values_supported'] = $algorithms;
            }
            if ($this->introspectionEndpoint !== null) {
                $metadata['introspection_endpoint_auth_signing_alg_values_supported'] = $algorithms;
            }
        }
        if ($this->dpopSigningAlgorithms !== []) {
            $metadata['dpop_signing_alg_values_supported'] = self::algorithmValues($this->dpopSigningAlgorithms);
        }

        return $metadata;
    }

    /**
     * @param list<AsymmetricJwtAlgorithm> $algorithms
     * @return list<string>
     */
    private static function algorithmValues(array $algorithms): array
    {
        return array_map(
            static fn(AsymmetricJwtAlgorithm $algorithm): string => $algorithm->value,
            $algorithms,
        );
    }

    private static function assertIssuer(string $issuer): void
    {
        if (!self::validHttpsUri($issuer, allowQuery: false)) {
            throw new ConfigurationException('OAuth authorization-server issuer must be an absolute HTTPS URI without query or fragment.');
        }
    }

    /**
     * @param array<array-key, mixed> $algorithms
     * @return list<AsymmetricJwtAlgorithm>
     */
    private static function normalizeAlgorithms(array $algorithms, string $label): array
    {
        if (!array_is_list($algorithms) || count($algorithms) > count(AsymmetricJwtAlgorithm::cases())) {
            throw new ConfigurationException($label . ' must be a bounded list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($algorithms as $algorithm) {
            if (!$algorithm instanceof AsymmetricJwtAlgorithm || isset($seen[$algorithm->value])) {
                throw new ConfigurationException($label . ' must contain unique asymmetric JWT algorithms.');
            }
            $seen[$algorithm->value] = true;
            $normalized[] = $algorithm;
        }

        return $normalized;
    }

    private static function validHttpsUri(string $uri, bool $allowQuery = true): bool
    {
        $parts = parse_url($uri);

        return is_array($parts)
            && strtolower((string) ($parts['scheme'] ?? '')) === 'https'
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== ''
            && !isset($parts['user'], $parts['pass'], $parts['fragment'])
            && ($allowQuery || !isset($parts['query']));
    }

    private function assertEndpoint(OAuthEndpointCapability $capability, ?string $uri, string $label): void
    {
        if ($this->capabilities->supportsEndpoint($capability)) {
            if ($uri === null || !self::validHttpsUri($uri)) {
                throw new ConfigurationException(sprintf('OAuth %s must be an absolute HTTPS URI.', $label));
            }

            return;
        }
        if ($uri !== null) {
            throw new ConfigurationException(sprintf('OAuth %s URI was supplied without the matching endpoint capability.', $label));
        }
    }
}
