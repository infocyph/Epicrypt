<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAssertionStatus;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAssertionValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientKeySet;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Tests\Support\InMemoryJwtReplayStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use Psr\Clock\ClockInterface;

function oauthAssertionClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return (new DateTimeImmutable('@' . $this->timestamp))->setTimezone(new DateTimeZone('UTC'));
        }
    };
}

/** @return array{OAuthClient, string, string, int} */
function oauthAssertionFixture(): array
{
    $pair = KeyPairGenerator::ec()->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk(
        $pair['public'],
        'client-key-1',
        AsymmetricJwtAlgorithm::ES256,
    );
    $client = new OAuthClient(
        clientId: 'service-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT],
        assertionKeys: new OAuthClientKeySet(['keys' => [$jwk]]),
    );

    return [$client, $pair['private'], 'https://auth.example.com/oauth/token', 1_700_000_000];
}

/** @param array<string, mixed> $overrides */
function oauthSignedAssertion(string $privateKey, string $audience, int $now, array $overrides = [], bool $withKid = true, array $headers = []): string
{
    $claims = [
        'iss' => 'service-client',
        'sub' => 'service-client',
        'aud' => $audience,
        'iat' => $now,
        'exp' => $now + 120,
        'jti' => 'assertion-' . hash('sha256', json_encode($overrides, JSON_THROW_ON_ERROR)),
        ...$overrides,
    ];

    return Jws::signer(
        $privateKey,
        AsymmetricJwtAlgorithm::ES256,
        $withKid ? 'client-key-1' : null,
    )->signCompact(
        json_encode($claims, JSON_THROW_ON_ERROR),
        ['typ' => 'JWT', ...$headers],
    );
}

it('validates a bounded private_key_jwt assertion once', function () {
    [$client, $privateKey, $audience, $now] = oauthAssertionFixture();
    $validator = new OAuthClientAssertionValidator(new InMemoryJwtReplayStore(), oauthAssertionClock($now));
    $assertion = oauthSignedAssertion($privateKey, $audience, $now);

    $first = $validator->validate($client, $assertion, $audience);
    $second = $validator->validate($client, $assertion, $audience);

    expect($first->valid)->toBeTrue()
        ->and($first->status)->toBe(OAuthClientAssertionStatus::VALID)
        ->and($first->claims['sub'])->toBe('service-client')
        ->and($second->valid)->toBeFalse()
        ->and($second->status)->toBe(OAuthClientAssertionStatus::REPLAYED);
});

it('accepts an assertion without kid only when the registered key is unambiguous', function () {
    [$client, $privateKey, $audience, $now] = oauthAssertionFixture();
    $validator = new OAuthClientAssertionValidator(new InMemoryJwtReplayStore(), oauthAssertionClock($now));
    $assertion = oauthSignedAssertion($privateKey, $audience, $now, withKid: false);

    expect($validator->validate($client, $assertion, $audience)->valid)->toBeTrue();
});

it('rejects invalid assertion claims and temporal windows', function () {
    [$client, $privateKey, $audience, $now] = oauthAssertionFixture();
    $validator = new OAuthClientAssertionValidator(new InMemoryJwtReplayStore(), oauthAssertionClock($now));

    $wrongAudience = oauthSignedAssertion($privateKey, $audience, $now, ['aud' => 'https://other.example/token']);
    $wrongSubject = oauthSignedAssertion($privateKey, $audience, $now, ['sub' => 'other-client']);
    $expired = oauthSignedAssertion($privateKey, $audience, $now, ['iat' => $now - 100, 'exp' => $now - 31]);
    $notYetValid = oauthSignedAssertion($privateKey, $audience, $now, ['nbf' => $now + 31]);

    expect($validator->validate($client, $wrongAudience, $audience)->status)->toBe(OAuthClientAssertionStatus::INVALID_CLAIMS)
        ->and($validator->validate($client, $wrongSubject, $audience)->status)->toBe(OAuthClientAssertionStatus::INVALID_CLAIMS)
        ->and($validator->validate($client, $expired, $audience)->status)->toBe(OAuthClientAssertionStatus::EXPIRED)
        ->and($validator->validate($client, $notYetValid, $audience)->status)->toBe(OAuthClientAssertionStatus::NOT_YET_VALID);
});

it('rejects attacker-controlled key location headers and wrong signatures', function () {
    [$client, $privateKey, $audience, $now] = oauthAssertionFixture();
    $validator = new OAuthClientAssertionValidator(new InMemoryJwtReplayStore(), oauthAssertionClock($now));
    $otherPair = KeyPairGenerator::ec()->generate();

    $keyInjection = oauthSignedAssertion(
        $privateKey,
        $audience,
        $now,
        headers: ['jku' => 'https://attacker.example/jwks.json'],
    );
    $wrongSignature = oauthSignedAssertion($otherPair['private'], $audience, $now);

    expect($validator->validate($client, $keyInjection, $audience)->status)->toBe(OAuthClientAssertionStatus::INVALID_HEADER)
        ->and($validator->validate($client, $wrongSignature, $audience)->status)->toBe(OAuthClientAssertionStatus::INVALID_SIGNATURE);
});
