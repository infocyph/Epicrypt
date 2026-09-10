<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeArtifact;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAssertionValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientKeySet;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenManager;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenPolicy;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryJwtReplayStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryPersonalAccessTokenStore;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;

/** @param Closure(): mixed $operation */
function runAuthParserBoundary(Closure $operation): void
{
    try {
        $operation();
    } catch (Error $error) {
        throw $error;
    } catch (Throwable) {
        // Domain/configuration rejection is expected for malformed protocol input.
    }
}

/** @return array<string, mixed> */
function authParserFixture(): array
{
    $issuer = 'https://auth-fuzz.example.test';
    $audience = 'https://api-fuzz.example.test';
    $assertionPair = KeyPairGenerator::ec()->generate();
    $assertionJwk = new Jwks()->exportPublicKeyToJwk(
        $assertionPair['public'],
        'assertion-key',
        AsymmetricJwtAlgorithm::ES256,
    );
    $client = new OAuthClient(
        clientId: 'fuzz-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: ['https://client-fuzz.example.test/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['read', 'openid'],
        audiences: [$audience],
        authenticationMethods: [OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT],
        assertionKeys: new OAuthClientKeySet(['keys' => [$assertionJwk]]),
    );
    $clients = new InMemoryOAuthClientStore([$client]);

    $codeArtifact = new AuthorizationCodeArtifact(new KeyRing([
        new KeyRingEntry(
            'code-key',
            random_bytes(32),
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: $issuer,
        ),
    ]), $issuer);
    $refreshArtifact = new RefreshTokenArtifact(new KeyRing([
        new KeyRingEntry(
            'refresh-key',
            random_bytes(32),
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: $issuer,
        ),
    ]), $issuer);

    $signingPair = sodium_crypto_sign_keypair();
    $privateKey = sodium_crypto_sign_secretkey($signingPair);
    $publicKey = sodium_crypto_sign_publickey($signingPair);
    $patKeys = new AsymmetricSigningKeySet(
        issuer: $issuer,
        activeKeyId: 'pat-key',
        privateKey: $privateKey,
        publicKeys: new KeyRing([
            new KeyRingEntry(
                'pat-key',
                $publicKey,
                KeyStatus::ACTIVE,
                KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
                AsymmetricJwtAlgorithm::EDDSA->value,
                issuer: $issuer,
            ),
        ]),
        algorithm: AsymmetricJwtAlgorithm::EDDSA,
        purpose: KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
    );

    return [
        'authorization' => new OAuthAuthorizationRequestValidator($clients),
        'assertion' => new OAuthClientAssertionValidator(new InMemoryJwtReplayStore()),
        'client' => $client,
        'code' => $codeArtifact,
        'refresh' => $refreshArtifact,
        'dpop' => new DpopProof(),
        'replay' => new InMemoryJwtReplayStore(),
        'id-token' => AsymmetricJwt::verifier(
            $publicKey,
            JwtPolicy::openIdIdToken($issuer, 'fuzz-client'),
            AsymmetricJwtAlgorithm::EDDSA,
        ),
        'pat' => new PersonalAccessTokenManager(
            $patKeys,
            new InMemoryPersonalAccessTokenStore(),
            new PersonalAccessTokenPolicy($audience),
        ),
        'audience' => $audience,
    ];
}

it('rejects a deterministic authentication parser corpus without crashes or hangs', function () {
    $fixture = authParserFixture();
    $corpus = [
        '', '.', '..', '...', '....',
        '%', '%0', '%GG', "\0", "\xFF",
        '{', '[', ']', '}', '{"a":1,"a":2}', '{"a":"\\uD800"}',
        str_repeat('.', 16),
        str_repeat('A', 16_385),
        'a=b&a=c', 'client_id=x&client_id=y',
    ];

    foreach ($corpus as $input) {
        runAuthParserBoundary(fn () => $fixture['authorization']->validate([
            'client_id' => $input,
            'redirect_uri' => 'https://client-fuzz.example.test/callback',
            'response_type' => 'code',
            'scope' => 'read',
            'code_challenge' => str_repeat('A', 43),
            'code_challenge_method' => 'S256',
        ]));
        runAuthParserBoundary(fn () => $fixture['assertion']->validate(
            $fixture['client'],
            $input,
            $fixture['issuer'] ?? 'https://auth-fuzz.example.test/token',
        ));
        runAuthParserBoundary(fn () => $fixture['code']->decrypt($input));
        runAuthParserBoundary(fn () => $fixture['refresh']->decryptForStateResolution($input));
        runAuthParserBoundary(fn () => $fixture['dpop']->verifyResult(
            $input,
            'POST',
            'https://api-fuzz.example.test/resource',
            AsymmetricJwtAlgorithm::EDDSA,
            $fixture['replay'],
        ));
        runAuthParserBoundary(fn () => $fixture['id-token']->verifyResult($input));
        runAuthParserBoundary(fn () => $fixture['pat']->verify($input));
    }

    expect(true)->toBeTrue();
});
