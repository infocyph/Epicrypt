<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeArtifact;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenService;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationApproval;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeConsumer;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeIssuer;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequest;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationServerMetadata;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationResult;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientSecret;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapability;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapabilityCatalog;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthIntrospectionEndpoint;
use Infocyph\Epicrypt\Auth\OAuth\OAuthJwksPublisher;
use Infocyph\Epicrypt\Auth\OAuth\OAuthRevocationEndpoint;
use Infocyph\Epicrypt\Auth\OAuth\OAuthTokenEndpoint;
use Infocyph\Epicrypt\Auth\OAuth\OAuthTokenTypeHint;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenManager;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryAuthorizationCodeStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthAccessTokenStatusStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthAuthorizationStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Psr\Clock\ClockInterface;

/** @return array<string, mixed> */
function phaseEFixture(): array
{
    $now = 1_700_000_000;
    $clock = new class($now) implements ClockInterface {
        public function __construct(private int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
    $issuer = 'https://auth.example.test';
    $audience = 'https://api.example.test';
    $keyPair = sodium_crypto_sign_keypair();
    $privateKey = sodium_crypto_sign_secretkey($keyPair);
    $publicKey = sodium_crypto_sign_publickey($keyPair);
    $accessRing = new KeyRing([
        new KeyRingEntry(
            'oauth-access-active',
            $publicKey,
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
            AsymmetricJwtAlgorithm::EDDSA->value,
            issuer: $issuer,
        ),
    ], $clock);
    $signingKeys = new AsymmetricSigningKeySet(
        issuer: $issuer,
        activeKeyId: 'oauth-access-active',
        privateKey: $privateKey,
        publicKeys: $accessRing,
        algorithm: AsymmetricJwtAlgorithm::EDDSA,
        purpose: KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
    );
    $codeRing = new KeyRing([
        new KeyRingEntry(
            'oauth-code-active',
            random_bytes(32),
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: $issuer,
        ),
    ], $clock);
    $refreshRing = new KeyRing([
        new KeyRingEntry(
            'oauth-refresh-active',
            random_bytes(32),
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: $issuer,
        ),
    ], $clock);

    $client = new OAuthClient(
        clientId: 'confidential-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: ['https://client.example.test/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::REFRESH_TOKEN, OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['orders:read', 'orders:write'],
        audiences: [$audience],
        authenticationMethods: [OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC],
        secret: OAuthClientSecret::fromHash(password_hash('phase-e-secret', PASSWORD_BCRYPT, ['cost' => 4])),
    );
    $clients = new InMemoryOAuthClientStore([$client]);
    $authorizations = new InMemoryOAuthAuthorizationStore();
    $codes = new InMemoryAuthorizationCodeStore();
    $refreshStore = new InMemoryRefreshTokenStore();
    $statuses = new InMemoryOAuthAccessTokenStatusStore();
    $codeArtifact = new AuthorizationCodeArtifact($codeRing, $issuer, $clock);
    $refreshArtifact = new RefreshTokenArtifact($refreshRing, $issuer, $clock);
    $refreshTokens = new RefreshTokenManager($refreshStore, $refreshArtifact, $clock);
    $accessTokens = new OAuthAccessTokenService($signingKeys, $authorizations, $statuses, clock: $clock);
    $codeConsumer = new OAuthAuthorizationCodeConsumer($codeArtifact, $codes, $authorizations, $clock);
    $tokenEndpoint = new OAuthTokenEndpoint(
        clients: $clients,
        accessTokens: $accessTokens,
        authorizationCodes: $codeConsumer,
        refreshTokens: $refreshTokens,
        authorizations: $authorizations,
        clock: $clock,
    );

    return compact(
        'now', 'clock', 'issuer', 'audience', 'signingKeys', 'client', 'clients', 'authorizations', 'codes',
        'codeArtifact', 'refreshTokens', 'accessTokens', 'tokenEndpoint',
    );
}

function phaseEAuthorizationCode(array $fixture): string
{
    $verifier = str_repeat('A', 43);
    $challenge = sodium_bin2base64(hash('sha256', $verifier, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $request = new OAuthAuthorizationRequest(
        clientId: $fixture['client']->clientId,
        redirectUri: 'https://client.example.test/callback',
        scopes: ['orders:read'],
        audiences: [$fixture['audience']],
        codeChallenge: $challenge,
        state: 'phase-e-state',
    );
    $approval = new OAuthAuthorizationApproval(
        subject: 'user-1',
        scopes: ['orders:read'],
        authenticationTime: $fixture['now'],
        authorizationLifetimeSeconds: 3_600,
        authenticationContext: 'urn:example:acr:password',
        authenticationMethods: ['pwd'],
    );
    $issued = new OAuthAuthorizationCodeIssuer(
        $fixture['authorizations'],
        $fixture['codes'],
        $fixture['codeArtifact'],
        $fixture['clock'],
    )->issue($request, $approval);

    return $issued->token;
}

it('executes authorization-code, refresh, introspection, reuse and revocation lifecycle', function () {
    $fixture = phaseEFixture();
    $authentication = OAuthClientAuthenticationResult::success($fixture['client']);
    $code = phaseEAuthorizationCode($fixture);

    $issued = $fixture['tokenEndpoint']->authorizationCode(
        clientId: $fixture['client']->clientId,
        authentication: $authentication,
        code: $code,
        redirectUri: 'https://client.example.test/callback',
        pkceVerifier: str_repeat('A', 43),
    );
    expect($issued->successful())->toBeTrue()
        ->and($issued->response?->accessToken)->not->toBeNull()
        ->and($issued->response?->refreshToken)->not->toBeNull();

    $introspection = new OAuthIntrospectionEndpoint($fixture['accessTokens'], $fixture['refreshTokens']);
    $accessBefore = $introspection->introspect($authentication, $issued->response->accessToken, OAuthTokenTypeHint::ACCESS_TOKEN);
    $refreshBefore = $introspection->introspect($authentication, $issued->response->refreshToken, OAuthTokenTypeHint::REFRESH_TOKEN);
    expect($accessBefore->response?->active)->toBeTrue()
        ->and($accessBefore->response?->metadata['client_id'] ?? null)->toBe($fixture['client']->clientId)
        ->and($refreshBefore->response?->active)->toBeTrue();

    $rotated = $fixture['tokenEndpoint']->refreshToken(
        clientId: $fixture['client']->clientId,
        authentication: $authentication,
        refreshToken: $issued->response->refreshToken,
        requestedScopes: ['orders:read'],
    );
    expect($rotated->successful())->toBeTrue()
        ->and($rotated->response?->refreshToken)->not->toBe($issued->response->refreshToken);

    $reused = $fixture['tokenEndpoint']->refreshToken(
        clientId: $fixture['client']->clientId,
        authentication: $authentication,
        refreshToken: $issued->response->refreshToken,
    );
    expect($reused->successful())->toBeFalse()
        ->and($reused->error?->code)->toBe(OAuthErrorCode::INVALID_GRANT)
        ->and($introspection->introspect(
            $authentication,
            $rotated->response->refreshToken,
            OAuthTokenTypeHint::REFRESH_TOKEN,
        )->response?->active)->toBeFalse();

    $code2 = phaseEAuthorizationCode($fixture);
    $issued2 = $fixture['tokenEndpoint']->authorizationCode(
        $fixture['client']->clientId,
        $authentication,
        $code2,
        'https://client.example.test/callback',
        str_repeat('A', 43),
    );
    $revocation = new OAuthRevocationEndpoint(
        $fixture['clients'],
        $fixture['accessTokens'],
        $fixture['refreshTokens'],
        $fixture['authorizations'],
        $fixture['clock'],
    );
    expect($revocation->revoke(
        $fixture['client']->clientId,
        $authentication,
        $issued2->response->refreshToken,
        OAuthTokenTypeHint::REFRESH_TOKEN,
    )->accepted)->toBeTrue()
        ->and($introspection->introspect(
            $authentication,
            $issued2->response->accessToken,
            OAuthTokenTypeHint::ACCESS_TOKEN,
        )->response?->active)->toBeFalse();
});

it('issues and immediately revokes client-credentials RFC 9068 access JWTs', function () {
    $fixture = phaseEFixture();
    $authentication = OAuthClientAuthenticationResult::success($fixture['client']);
    $issued = $fixture['tokenEndpoint']->clientCredentials($authentication, ['orders:read']);
    expect($issued->successful())->toBeTrue()
        ->and($issued->response?->refreshToken)->toBeNull();

    $introspection = new OAuthIntrospectionEndpoint($fixture['accessTokens'], $fixture['refreshTokens']);
    expect($introspection->introspect(
        $authentication,
        $issued->response->accessToken,
        OAuthTokenTypeHint::ACCESS_TOKEN,
    )->response?->active)->toBeTrue();

    $revocation = new OAuthRevocationEndpoint(
        $fixture['clients'],
        $fixture['accessTokens'],
        $fixture['refreshTokens'],
        $fixture['authorizations'],
        $fixture['clock'],
    );
    expect($revocation->revoke(
        $fixture['client']->clientId,
        $authentication,
        $issued->response->accessToken,
        OAuthTokenTypeHint::ACCESS_TOKEN,
    )->accepted)->toBeTrue()
        ->and($introspection->introspect(
            $authentication,
            $issued->response->accessToken,
            OAuthTokenTypeHint::ACCESS_TOKEN,
        )->response?->active)->toBeFalse();
});

it('keeps RFC 7009 non-oracular and RFC 7662 protected', function () {
    $fixture = phaseEFixture();
    $authentication = OAuthClientAuthenticationResult::success($fixture['client']);
    $revocation = new OAuthRevocationEndpoint(
        $fixture['clients'],
        $fixture['accessTokens'],
        $fixture['refreshTokens'],
        $fixture['authorizations'],
        $fixture['clock'],
    );
    expect($revocation->revoke(
        $fixture['client']->clientId,
        $authentication,
        'not-a-real-token',
        OAuthTokenTypeHint::ACCESS_TOKEN,
    )->accepted)->toBeTrue();

    $introspection = new OAuthIntrospectionEndpoint($fixture['accessTokens'], $fixture['refreshTokens']);
    $failed = OAuthClientAuthenticationResult::failure(
        Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationFailureReason::INVALID_CLIENT,
    );
    expect($introspection->introspect($failed, 'not-a-real-token')->error)->toBe(OAuthErrorCode::INVALID_CLIENT)
        ->and($introspection->introspect($authentication, 'not-a-real-token')->response?->toArray())
        ->toBe(['active' => false]);
});

it('publishes purpose-scoped JWKS and capability-accurate RFC 8414 metadata', function () {
    $fixture = phaseEFixture();
    $jwks = new OAuthJwksPublisher($fixture['signingKeys'])->document();
    expect($jwks['keys'])->toHaveCount(1)
        ->and($jwks['keys'][0]['kid'] ?? null)->toBe('oauth-access-active')
        ->and($jwks['keys'][0])->not->toHaveKey('d');

    $catalog = new OAuthEndpointCapabilityCatalog(
        endpoints: [
            OAuthEndpointCapability::AUTHORIZATION,
            OAuthEndpointCapability::TOKEN,
            OAuthEndpointCapability::REVOCATION,
            OAuthEndpointCapability::INTROSPECTION,
            OAuthEndpointCapability::METADATA,
            OAuthEndpointCapability::JWKS,
        ],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::CLIENT_CREDENTIALS, OAuthGrantType::REFRESH_TOKEN],
        clientAuthenticationMethods: [
            OAuthClientAuthenticationMethod::NONE,
            OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC,
            OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT,
        ],
    );
    $metadata = new OAuthAuthorizationServerMetadata(
        issuer: $fixture['issuer'],
        capabilities: $catalog,
        authorizationEndpoint: $fixture['issuer'] . '/authorize',
        tokenEndpoint: $fixture['issuer'] . '/token',
        revocationEndpoint: $fixture['issuer'] . '/revoke',
        introspectionEndpoint: $fixture['issuer'] . '/introspect',
        jwksUri: $fixture['issuer'] . '/jwks.json',
        dpopSigningAlgorithms: [AsymmetricJwtAlgorithm::ES256],
        clientAssertionSigningAlgorithms: [AsymmetricJwtAlgorithm::ES256],
    )->toArray();

    expect($metadata['issuer'])->toBe($fixture['issuer'])
        ->and($metadata['response_types_supported'])->toBe(['code'])
        ->and($metadata['code_challenge_methods_supported'])->toBe(['S256'])
        ->and($metadata['authorization_response_iss_parameter_supported'])->toBeTrue()
        ->and($metadata['dpop_signing_alg_values_supported'])->toBe(['ES256'])
        ->and($metadata['introspection_endpoint_auth_methods_supported'])->not->toContain('none');
});
