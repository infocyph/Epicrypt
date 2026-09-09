<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAssertionStatus;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAssertionValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationFailureReason;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientKeySet;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientSecret;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Tests\Support\InMemoryJwtReplayStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use Psr\Clock\ClockInterface;

it('authenticates allowed client-secret methods without exposing transport parsing', function () {
    $secret = 'a-secret-value-long-enough-for-a-real-client';
    $client = new OAuthClient(
        clientId: 'secret-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC],
        secret: OAuthClientSecret::hash($secret),
    );
    $authenticator = new OAuthClientAuthenticator(
        new InMemoryOAuthClientStore([$client]),
        new OAuthClientAssertionValidator(new InMemoryJwtReplayStore()),
    );

    expect($authenticator->authenticateSecret('secret-client', OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC, $secret)->authenticated)->toBeTrue()
        ->and($authenticator->authenticateSecret('secret-client', OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC, 'wrong')->reason)->toBe(OAuthClientAuthenticationFailureReason::INVALID_SECRET)
        ->and($authenticator->authenticateSecret('secret-client', OAuthClientAuthenticationMethod::CLIENT_SECRET_POST, $secret)->reason)->toBe(OAuthClientAuthenticationFailureReason::METHOD_NOT_ALLOWED)
        ->and($authenticator->authenticateSecret('missing-client', OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC, $secret)->reason)->toBe(OAuthClientAuthenticationFailureReason::INVALID_CLIENT);
});

it('authenticates private_key_jwt and exposes replay only as an audit-safe internal reason', function () {
    $pair = KeyPairGenerator::ec()->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk($pair['public'], 'client-key-1', AsymmetricJwtAlgorithm::ES256);
    $client = new OAuthClient(
        clientId: 'jwt-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT],
        assertionKeys: new OAuthClientKeySet(['keys' => [$jwk]]),
    );
    $now = 1_700_000_000;
    $clock = new class($now) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return (new DateTimeImmutable('@' . $this->timestamp))->setTimezone(new DateTimeZone('UTC'));
        }
    };
    $audience = 'https://auth.example.com/oauth/token';
    $assertion = Jws::signer($pair['private'], AsymmetricJwtAlgorithm::ES256, 'client-key-1')->signCompact(
        json_encode([
            'iss' => 'jwt-client',
            'sub' => 'jwt-client',
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => 'assertion-1',
        ], JSON_THROW_ON_ERROR),
        ['typ' => 'JWT'],
    );
    $authenticator = new OAuthClientAuthenticator(
        new InMemoryOAuthClientStore([$client]),
        new OAuthClientAssertionValidator(new InMemoryJwtReplayStore(), $clock),
    );

    $first = $authenticator->authenticatePrivateKeyJwt('jwt-client', $assertion, $audience);
    $second = $authenticator->authenticatePrivateKeyJwt('jwt-client', $assertion, $audience);

    expect($first->authenticated)->toBeTrue()
        ->and($second->authenticated)->toBeFalse()
        ->and($second->reason)->toBe(OAuthClientAuthenticationFailureReason::REPLAYED_ASSERTION)
        ->and($second->assertionStatus)->toBe(OAuthClientAssertionStatus::REPLAYED);
});
