<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeArtifact;
use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Psr\Clock\ClockInterface;

function oauthAuthorizationCodeClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function oauthAuthorizationCodeRing(string $key, KeyStatus $status = KeyStatus::ACTIVE): KeyRing
{
    return new KeyRing([
        new KeyRingEntry(
            'oauth-code-v1',
            $key,
            $status,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: 'https://issuer.example',
        ),
    ], oauthAuthorizationCodeClock(2_000));
}

it('issues and decrypts a bounded authorization-code JWE with exchange bindings', function () {
    $key = random_bytes(32);
    $verifier = str_repeat('A', 43);
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));
    $artifact = new AuthorizationCodeArtifact(
        oauthAuthorizationCodeRing($key),
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_000),
    );

    $issue = $artifact->issue(
        authorizationId: 'authorization-7',
        subject: 'user-7',
        clientId: 'client-1',
        redirectUri: 'https://client.example/callback',
        pkceChallenge: $challenge,
        scopes: ['openid', 'orders:read'],
        audiences: ['orders-api'],
        nonce: 'browser-nonce',
        authenticationTime: 1_900,
        authenticationContext: 'urn:example:acr:mfa',
        authenticationMethods: ['pwd', 'otp'],
    );

    expect(explode('.', $issue->token))->toHaveCount(5)
        ->and($issue->code->codeId)->toMatch('/\A[A-Za-z0-9_-]{32}\z/D')
        ->and($issue->code->expiresAt)->toBe(2_300)
        ->and($issue->code->matchesClient('client-1'))->toBeTrue()
        ->and($issue->code->matchesClient('client-2'))->toBeFalse()
        ->and($issue->code->matchesRedirectUri('https://client.example/callback'))->toBeTrue()
        ->and($issue->code->matchesRedirectUri('https://client.example/other'))->toBeFalse()
        ->and($issue->code->matchesPkceVerifier($verifier))->toBeTrue()
        ->and($issue->code->matchesPkceVerifier(str_repeat('B', 43)))->toBeFalse()
        ->and($issue->code->matchesPkceVerifier('short'))->toBeFalse();

    $decoded = $artifact->decrypt($issue->token);
    expect($decoded->codeId)->toBe($issue->code->codeId)
        ->and($decoded->authorizationId)->toBe('authorization-7')
        ->and($decoded->subject)->toBe('user-7')
        ->and($decoded->clientId)->toBe('client-1')
        ->and($decoded->scopes)->toBe(['openid', 'orders:read'])
        ->and($decoded->audiences)->toBe(['orders-api'])
        ->and($decoded->nonce)->toBe('browser-nonce')
        ->and($decoded->authenticationTime)->toBe(1_900)
        ->and($decoded->authenticationContext)->toBe('urn:example:acr:mfa')
        ->and($decoded->authenticationMethods)->toBe(['pwd', 'otp']);
});

it('decrypts with a fallback rotation key but rejects the same kid in another purpose domain', function () {
    $key = random_bytes(32);
    $challenge = Base64Url::encode(hash('sha256', str_repeat('V', 43), true));
    $issuer = new AuthorizationCodeArtifact(
        oauthAuthorizationCodeRing($key),
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_000),
    );
    $token = $issuer->issue(
        'authorization-1',
        'user-1',
        'client-1',
        'https://client.example/callback',
        $challenge,
        ['orders:read'],
        ['orders-api'],
    )->token;

    $fallback = new AuthorizationCodeArtifact(
        oauthAuthorizationCodeRing($key, KeyStatus::FALLBACK),
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_100),
    );
    expect($fallback->decrypt($token)->clientId)->toBe('client-1');

    $wrongPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-code-v1',
            $key,
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: 'https://issuer.example',
        ),
    ], oauthAuthorizationCodeClock(2_100));
    expect(fn () => new AuthorizationCodeArtifact(
        $wrongPurpose,
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_100),
    )->decrypt($token))->toThrow(InvalidTokenException::class);
});

it('rejects cross-token JOSE type substitution before accepting authorization-code claims', function () {
    $key = random_bytes(32);
    $verifier = str_repeat('C', 43);
    $challenge = Base64Url::encode(hash('sha256', $verifier, true));
    $artifact = new AuthorizationCodeArtifact(
        oauthAuthorizationCodeRing($key),
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_000),
    );
    $issue = $artifact->issue(
        'authorization-1',
        'user-1',
        'client-1',
        'https://client.example/callback',
        $challenge,
        ['orders:read'],
        ['orders-api'],
    );

    $wrongType = new Jwe($key, keyId: 'oauth-code-v1')->encryptCompact(
        Json::encode($issue->code->toArray()),
        ['typ' => AuthTokenClass::OAUTH_REFRESH_TOKEN->joseType()],
    );

    expect(fn () => $artifact->decrypt($wrongType))->toThrow(InvalidTokenException::class);
});

it('rejects expired, future-issued, extended, and profile-mutated authorization codes', function () {
    $key = random_bytes(32);
    $challenge = Base64Url::encode(hash('sha256', str_repeat('D', 43), true));
    $ring = oauthAuthorizationCodeRing($key);
    $issuer = new AuthorizationCodeArtifact($ring, 'https://issuer.example', oauthAuthorizationCodeClock(2_000));
    $issue = $issuer->issue(
        'authorization-1',
        'user-1',
        'client-1',
        'https://client.example/callback',
        $challenge,
        ['orders:read'],
        ['orders-api'],
    );

    $expired = new AuthorizationCodeArtifact($ring, 'https://issuer.example', oauthAuthorizationCodeClock(2_300));
    expect(fn () => $expired->decrypt($issue->token))->toThrow(InvalidTokenException::class);

    $encrypt = static fn(array $claims): string => new Jwe($key, keyId: 'oauth-code-v1')->encryptCompact(
        Json::encode($claims),
        ['typ' => AuthTokenClass::OAUTH_AUTHORIZATION_CODE->joseType()],
    );
    $futureClaims = array_replace($issue->code->toArray(), ['iat' => 2_031, 'exp' => 2_331]);
    $longClaims = array_replace($issue->code->toArray(), ['exp' => 2_601]);
    $extraClaims = $issue->code->toArray() + ['unexpected' => 'value'];
    $wrongUse = array_replace($issue->code->toArray(), ['token_use' => 'refresh_token']);
    $plainPkce = array_replace($issue->code->toArray(), ['code_challenge_method' => 'plain']);

    expect(fn () => $issuer->decrypt($encrypt($futureClaims)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $issuer->decrypt($encrypt($longClaims)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $issuer->decrypt($encrypt($extraClaims)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $issuer->decrypt($encrypt($wrongUse)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $issuer->decrypt($encrypt($plainPkce)))->toThrow(InvalidTokenException::class);
});

it('rejects invalid issuance state before producing an authorization code', function () {
    $key = random_bytes(32);
    $artifact = new AuthorizationCodeArtifact(
        oauthAuthorizationCodeRing($key),
        'https://issuer.example',
        oauthAuthorizationCodeClock(2_000),
    );
    $challenge = Base64Url::encode(hash('sha256', str_repeat('E', 43), true));

    expect(fn () => $artifact->issue(
        'authorization-1',
        'user-1',
        'client-1',
        'https://client.example/callback',
        'not-a-valid-s256-challenge',
        ['orders:read'],
        ['orders-api'],
    ))->toThrow(ConfigurationException::class)
        ->and(fn () => $artifact->issue(
            'authorization-1',
            'user-1',
            'client-1',
            'https://client.example/callback',
            $challenge,
            ['orders:read', 'orders:read'],
            ['orders-api'],
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => $artifact->issue(
            'authorization-1',
            'user-1',
            'client-1',
            'https://client.example/callback',
            $challenge,
            ['orders:read'],
            ['orders-api'],
            nonce: 'nonce-without-openid',
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => $artifact->issue(
            'authorization-1',
            'user-1',
            'client-1',
            'https://client.example/callback',
            $challenge,
            ['orders:read'],
            ['orders-api'],
            lifetimeSeconds: AuthorizationCode::MAXIMUM_LIFETIME_SECONDS + 1,
        ))->toThrow(ConfigurationException::class);
});
