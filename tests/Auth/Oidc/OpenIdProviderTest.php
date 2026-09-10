<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenIssue;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationServerMetadata;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapability;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapabilityCatalog;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdClaimsProviderInterface;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdIdTokenIssuer;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdProviderMetadata;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdSubjectIdentifierProviderInterface;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdSubjectType;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdTokenResponseExtension;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdUserInfoProjector;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Psr\Clock\ClockInterface;

function oidcProviderClock(int $timestamp = 1_700_000_100): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function oidcProviderSubjects(): OpenIdSubjectIdentifierProviderInterface
{
    return new class implements OpenIdSubjectIdentifierProviderInterface {
        public function subject(string $principalId, string $clientId): string
        {
            return hash('sha256', $clientId . "\0" . $principalId);
        }
    };
}

function oidcProviderSigningKeys(KeyPurpose $purpose = KeyPurpose::OIDC_ID_TOKEN_SIGNING): AsymmetricSigningKeySet
{
    $issuer = 'https://issuer.example.test';
    $pair = sodium_crypto_sign_keypair();
    $private = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $ring = new KeyRing([
        new KeyRingEntry('oidc-active', $public, KeyStatus::ACTIVE, $purpose, 'EdDSA', issuer: $issuer),
    ]);

    return new AsymmetricSigningKeySet(
        issuer: $issuer,
        activeKeyId: 'oidc-active',
        privateKey: $private,
        publicKeys: $ring,
        algorithm: AsymmetricJwtAlgorithm::EDDSA,
        purpose: $purpose,
    );
}

function oidcProviderAuthorizationCode(ClockInterface $clock): AuthorizationCode
{
    return AuthorizationCode::issue(
        issuer: 'https://issuer.example.test',
        authorizationId: 'authorization-1',
        subject: 'principal-1',
        clientId: 'oidc-client',
        redirectUri: 'https://client.example.test/callback',
        pkceChallenge: str_repeat('A', 43),
        scopes: ['openid', 'profile'],
        audiences: ['https://api.example.test'],
        nonce: 'browser-nonce',
        authenticationTime: 1_700_000_000,
        authenticationContext: 'urn:example:loa2',
        authenticationMethods: ['pwd', 'otp'],
        clock: $clock,
    );
}

it('issues a signed OIDC ID token with subject authentication and hash claims', function () {
    $clock = oidcProviderClock();
    $keys = oidcProviderSigningKeys();
    $authorization = oidcProviderAuthorizationCode($clock);
    $issuer = new OpenIdIdTokenIssuer($keys, oidcProviderSubjects(), clock: $clock);

    $issue = $issuer->issue(
        $authorization,
        accessToken: 'access-token-value',
        authorizationCode: 'authorization-code-value',
        state: 'state-value',
    );
    $claims = $issue->claims->toArray();

    expect(substr_count($issue->token, '.'))->toBe(2)
        ->and($claims['iss'])->toBe('https://issuer.example.test')
        ->and($claims['aud'])->toBe(['oidc-client'])
        ->and($claims['nonce'])->toBe('browser-nonce')
        ->and($claims['auth_time'])->toBe(1_700_000_000)
        ->and($claims['acr'])->toBe('urn:example:loa2')
        ->and($claims['amr'])->toBe(['pwd', 'otp'])
        ->and($claims)->toHaveKeys(['at_hash', 'c_hash', 's_hash']);

    new OpenIdIdTokenValidator($clock)->validate(
        claims: $claims,
        signingAlgorithm: AsymmetricJwtAlgorithm::EDDSA,
        clientId: 'oidc-client',
        nonce: 'browser-nonce',
        accessToken: 'access-token-value',
        authorizationCode: 'authorization-code-value',
        state: 'state-value',
        maximumAuthenticationAge: 300,
    );

    expect(true)->toBeTrue();
});

it('adds id_token only to authorization-code responses carrying openid', function () {
    $clock = oidcProviderClock();
    $authorization = oidcProviderAuthorizationCode($clock);
    $idTokens = new OpenIdIdTokenIssuer(oidcProviderSigningKeys(), oidcProviderSubjects(), clock: $clock);
    $extension = new OpenIdTokenResponseExtension($idTokens);
    $accessClaims = JwtClaims::issue(
        issuer: 'https://issuer.example.test',
        subject: 'principal-1',
        audiences: ['https://api.example.test'],
        ttlSeconds: 300,
        clock: $clock,
    );
    $access = new OAuthAccessTokenIssue('access-token-value', $accessClaims);

    $parameters = $extension->parameters($authorization, $access, 'authorization-code-value');
    expect($parameters)->toHaveKey('id_token')
        ->and($parameters['id_token'])->toBeString();

    [, , , , $idTokenClaims] = JwtToken::parse($parameters['id_token']);
    new OpenIdIdTokenValidator($clock)->validate(
        claims: $idTokenClaims,
        signingAlgorithm: AsymmetricJwtAlgorithm::EDDSA,
        clientId: 'oidc-client',
        nonce: 'browser-nonce',
        accessToken: 'access-token-value',
        authorizationCode: 'authorization-code-value',
    );

    $oauthOnly = AuthorizationCode::issue(
        issuer: 'https://issuer.example.test',
        authorizationId: 'authorization-2',
        subject: 'principal-1',
        clientId: 'oidc-client',
        redirectUri: 'https://client.example.test/callback',
        pkceChallenge: str_repeat('A', 43),
        scopes: ['profile'],
        audiences: ['https://api.example.test'],
        authenticationTime: 1_700_000_000,
        clock: $clock,
    );

    expect($extension->parameters($oauthOnly, $access, 'oauth-code'))->toBe([]);
});

it('projects bounded UserInfo claims while keeping sub provider-owned', function () {
    $claims = new class implements OpenIdClaimsProviderInterface {
        public function claims(string $principalId, string $clientId, array $scopes): array
        {
            if ($principalId !== 'principal-1' || $clientId !== 'oidc-client') {
                return [];
            }

            return in_array('profile', $scopes, true) ? ['name' => 'Example User'] : [];
        }
    };
    $projector = new OpenIdUserInfoProjector(oidcProviderSubjects(), $claims);

    $result = $projector->project('principal-1', 'oidc-client', ['openid', 'profile']);
    expect($result)->toHaveKeys(['sub', 'name'])
        ->and($result['name'])->toBe('Example User')
        ->and($result['sub'])->not->toBe('principal-1');

    $badClaims = new class implements OpenIdClaimsProviderInterface {
        public function claims(string $principalId, string $clientId, array $scopes): array
        {
            return $principalId === 'principal-1' && $clientId === 'oidc-client' && $scopes === ['openid']
                ? ['sub' => 'override']
                : [];
        }
    };
    expect(fn () => new OpenIdUserInfoProjector(oidcProviderSubjects(), $badClaims)
        ->project('principal-1', 'oidc-client', ['openid']))
        ->toThrow(ConfigurationException::class);
});

it('projects OIDC discovery from explicit OAuth capabilities and signing policy', function () {
    $capabilities = new OAuthEndpointCapabilityCatalog(
        endpoints: [OAuthEndpointCapability::AUTHORIZATION, OAuthEndpointCapability::TOKEN, OAuthEndpointCapability::JWKS],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::REFRESH_TOKEN],
        clientAuthenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
    $oauth = new OAuthAuthorizationServerMetadata(
        issuer: 'https://issuer.example.test',
        capabilities: $capabilities,
        authorizationEndpoint: 'https://issuer.example.test/authorize',
        tokenEndpoint: 'https://issuer.example.test/token',
        jwksUri: 'https://issuer.example.test/jwks',
    );
    $metadata = new OpenIdProviderMetadata(
        oauth: $oauth,
        idTokenKeys: oidcProviderSigningKeys(),
        userInfoEndpoint: 'https://issuer.example.test/userinfo',
        subjectTypes: [OpenIdSubjectType::PUBLIC, OpenIdSubjectType::PAIRWISE],
        scopesSupported: ['openid', 'profile'],
        claimsSupported: ['sub', 'name'],
    );

    expect($metadata->toArray())
        ->toMatchArray([
            'issuer' => 'https://issuer.example.test',
            'userinfo_endpoint' => 'https://issuer.example.test/userinfo',
            'subject_types_supported' => ['public', 'pairwise'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid', 'profile'],
            'claims_supported' => ['sub', 'name'],
        ]);
});

it('rejects ID-token issuance with a non-OIDC signing-key purpose', function () {
    $clock = oidcProviderClock();

    expect(fn () => new OpenIdIdTokenIssuer(
        oidcProviderSigningKeys(KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING),
        oidcProviderSubjects(),
        clock: $clock,
    ))->toThrow(ConfigurationException::class);
});
