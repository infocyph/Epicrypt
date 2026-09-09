<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifactClaims;
use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Psr\Clock\ClockInterface;

function oauthRefreshArtifactClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function oauthRefreshArtifactRing(string $key, KeyStatus $status = KeyStatus::ACTIVE): KeyRing
{
    return new KeyRing([
        new KeyRingEntry(
            'oauth-refresh-v1',
            $key,
            $status,
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: 'https://issuer.example',
        ),
    ], oauthRefreshArtifactClock(2_000));
}

function oauthRefreshArtifactGrant(int $expiresAt, array $scopes = ['orders:read', 'orders:write']): RefreshTokenGrant
{
    return new RefreshTokenGrant(
        id: 'grant-7',
        subject: 'user-7',
        clientId: 'client-1',
        audiences: ['orders-api'],
        scopes: $scopes,
        expiresAt: $expiresAt,
        dpopKeyThumbprint: str_repeat('A', 43),
    );
}

it('issues and decrypts a refresh-token JWE that binds family and grant state', function () {
    $key = random_bytes(32);
    $artifact = new RefreshTokenArtifact(
        oauthRefreshArtifactRing($key),
        'https://issuer.example',
        oauthRefreshArtifactClock(2_000),
    );
    $issue = $artifact->issue(oauthRefreshArtifactGrant(5_600), idleLifetimeSeconds: 1_800);

    expect(explode('.', $issue->token))->toHaveCount(5)
        ->and($issue->claims->tokenId)->toMatch('/\A[A-Za-z0-9_-]{32}\z/D')
        ->and($issue->claims->familyId)->toMatch('/\A[A-Za-z0-9_-]{43}\z/D')
        ->and($issue->claims->issuedAt)->toBe(2_000)
        ->and($issue->claims->idleExpiresAt)->toBe(3_800)
        ->and($issue->claims->grant->clientId)->toBe('client-1')
        ->and($issue->claims->grant->scopes)->toBe(['orders:read', 'orders:write'])
        ->and($issue->claims->grant->dpopKeyThumbprint)->toBe(str_repeat('A', 43));

    $decoded = $artifact->decrypt($issue->token);
    expect($decoded->tokenId)->toBe($issue->claims->tokenId)
        ->and($decoded->familyId)->toBe($issue->claims->familyId)
        ->and($decoded->grant->id)->toBe('grant-7')
        ->and($decoded->grant->subject)->toBe('user-7')
        ->and($decoded->grant->audiences)->toBe(['orders-api'])
        ->and($decoded->grant->scopes)->toBe(['orders:read', 'orders:write']);
});

it('preserves a family across successor artifacts while allowing scope narrowing', function () {
    $key = random_bytes(32);
    $artifact = new RefreshTokenArtifact(
        oauthRefreshArtifactRing($key),
        'https://issuer.example',
        oauthRefreshArtifactClock(2_000),
    );
    $first = $artifact->issue(oauthRefreshArtifactGrant(5_600), idleLifetimeSeconds: 1_800);
    $narrowedGrant = oauthRefreshArtifactGrant(5_600, ['orders:read']);
    $successor = $artifact->issue(
        $narrowedGrant,
        familyId: $first->claims->familyId,
        idleLifetimeSeconds: 1_800,
    );

    expect($successor->claims->familyId)->toBe($first->claims->familyId)
        ->and($successor->claims->tokenId)->not->toBe($first->claims->tokenId)
        ->and($successor->claims->grant->scopes)->toBe(['orders:read']);
});

it('supports fallback protection keys and rejects an identical key in another purpose domain', function () {
    $key = random_bytes(32);
    $issuer = new RefreshTokenArtifact(
        oauthRefreshArtifactRing($key),
        'https://issuer.example',
        oauthRefreshArtifactClock(2_000),
    );
    $token = $issuer->issue(oauthRefreshArtifactGrant(5_600), idleLifetimeSeconds: 1_800)->token;

    $fallback = new RefreshTokenArtifact(
        oauthRefreshArtifactRing($key, KeyStatus::FALLBACK),
        'https://issuer.example',
        oauthRefreshArtifactClock(2_100),
    );
    expect($fallback->decrypt($token)->grant->clientId)->toBe('client-1');

    $wrongPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-refresh-v1',
            $key,
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: 'https://issuer.example',
        ),
    ], oauthRefreshArtifactClock(2_100));
    expect(fn () => new RefreshTokenArtifact(
        $wrongPurpose,
        'https://issuer.example',
        oauthRefreshArtifactClock(2_100),
    )->decrypt($token))->toThrow(InvalidTokenException::class);
});

it('rejects refresh-token type substitution, expired tokens, and mutated profile claims', function () {
    $key = random_bytes(32);
    $ring = oauthRefreshArtifactRing($key);
    $artifact = new RefreshTokenArtifact($ring, 'https://issuer.example', oauthRefreshArtifactClock(2_000));
    $issue = $artifact->issue(oauthRefreshArtifactGrant(5_600), idleLifetimeSeconds: 300);

    $wrongType = new Jwe($key, keyId: 'oauth-refresh-v1')->encryptCompact(
        Json::encode($issue->claims->toArray()),
        ['typ' => AuthTokenClass::OAUTH_AUTHORIZATION_CODE->joseType()],
    );
    expect(fn () => $artifact->decrypt($wrongType))->toThrow(InvalidTokenException::class);

    $expired = new RefreshTokenArtifact($ring, 'https://issuer.example', oauthRefreshArtifactClock(2_300));
    expect(fn () => $expired->decrypt($issue->token))->toThrow(InvalidTokenException::class);

    $encrypt = static fn(array $claims): string => new Jwe($key, keyId: 'oauth-refresh-v1')->encryptCompact(
        Json::encode($claims),
        ['typ' => AuthTokenClass::OAUTH_REFRESH_TOKEN->joseType()],
    );
    $future = array_replace($issue->claims->toArray(), ['iat' => 2_031, 'idle_exp' => 2_331, 'exp' => 5_631]);
    $wrongUse = array_replace($issue->claims->toArray(), ['token_use' => 'authorization_code']);
    $extra = $issue->claims->toArray() + ['unexpected' => true];

    expect(fn () => $artifact->decrypt($encrypt($future)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $artifact->decrypt($encrypt($wrongUse)))->toThrow(InvalidTokenException::class)
        ->and(fn () => $artifact->decrypt($encrypt($extra)))->toThrow(InvalidTokenException::class);
});

it('bounds refresh-token absolute and idle lifetime before encryption', function () {
    $key = random_bytes(32);
    $artifact = new RefreshTokenArtifact(
        oauthRefreshArtifactRing($key),
        'https://issuer.example',
        oauthRefreshArtifactClock(2_000),
    );

    expect(fn () => $artifact->issue(
        oauthRefreshArtifactGrant(2_000 + RefreshTokenArtifactClaims::MAXIMUM_ABSOLUTE_LIFETIME_SECONDS + 1),
    ))->toThrow(ConfigurationException::class)
        ->and(fn () => $artifact->issue(
            oauthRefreshArtifactGrant(5_600),
            idleLifetimeSeconds: RefreshTokenArtifact::MAXIMUM_IDLE_LIFETIME_SECONDS + 1,
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => $artifact->issue(oauthRefreshArtifactGrant(1_999)))
        ->toThrow(ConfigurationException::class);
});
