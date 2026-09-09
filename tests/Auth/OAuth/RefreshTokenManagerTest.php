<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenGrant;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenManager;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Psr\Clock\ClockInterface;

function oauthRefreshManagerClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}
        public function now(): DateTimeImmutable { return new DateTimeImmutable('@' . $this->timestamp); }
    };
}

function oauthRefreshManagerGrant(int $expiresAt, string $authorizationId = 'authorization-1'): RefreshTokenGrant
{
    return new RefreshTokenGrant(
        $authorizationId, 'user-42', 'browser-client', ['orders-api'], ['orders:read', 'orders:write'],
        $expiresAt, str_repeat('A', 43),
    );
}

function oauthRefreshManagerArtifact(string $key, ClockInterface $clock): RefreshTokenArtifact
{
    return new RefreshTokenArtifact(
        new KeyRing([
            new KeyRingEntry(
                'refresh-v1', $key, KeyStatus::ACTIVE, KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
                JweKeyManagementAlgorithm::DIRECT->value, issuer: 'https://issuer.example',
            ),
        ], $clock),
        'https://issuer.example', $clock,
    );
}

it('rotates JOSE refresh tokens once and revokes the family on ancestor reuse', function () {
    $clock = oauthRefreshManagerClock(1_700_000_000);
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), oauthRefreshManagerArtifact(random_bytes(32), $clock), $clock);
    $original = $manager->issue(oauthRefreshManagerGrant(1_700_086_400), 3_600);

    expect($manager->rotate($original, 'other-client', str_repeat('A', 43), 3_600)->status)->toBe(RefreshTokenRotationStatus::CLIENT_MISMATCH)
        ->and($manager->rotate($original, 'browser-client', str_repeat('A', 43), 3_600, ['orders:delete'])->status)->toBe(RefreshTokenRotationStatus::SCOPE_MISMATCH);

    $rotated = $manager->rotate($original, 'browser-client', str_repeat('A', 43), 3_600, ['orders:read']);
    expect($rotated->rotated)->toBeTrue()
        ->and($rotated->token)->not->toBeNull()
        ->and($rotated->token)->not->toBe($original)
        ->and($rotated->grant?->scopes)->toBe(['orders:read']);

    expect($manager->rotate($original, 'browser-client', str_repeat('A', 43), 3_600)->status)->toBe(RefreshTokenRotationStatus::REUSED)
        ->and($manager->rotate($rotated->token ?? '', 'browser-client', str_repeat('A', 43), 3_600)->status)->toBe(RefreshTokenRotationStatus::REVOKED);
});

it('preserves reuse detection precedence after a consumed ancestor reaches idle expiry', function () {
    $clock = oauthRefreshManagerClock(1_700_000_000);
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), oauthRefreshManagerArtifact(random_bytes(32), $clock), $clock);
    $original = $manager->issue(oauthRefreshManagerGrant(1_700_086_400), 60);
    $rotated = $manager->rotate($original, 'browser-client', str_repeat('A', 43), 60);
    expect($rotated->rotated)->toBeTrue();

    $clock->timestamp += 61;
    expect($manager->rotate($original, 'browser-client', str_repeat('A', 43), 60)->status)->toBe(RefreshTokenRotationStatus::REUSED)
        ->and($manager->rotate($rotated->token ?? '', 'browser-client', str_repeat('A', 43), 60)->status)->toBe(RefreshTokenRotationStatus::REVOKED);
});

it('enforces sender binding, idle expiry, family revoke, and authorization revoke', function () {
    $clock = oauthRefreshManagerClock(1_700_000_000);
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), oauthRefreshManagerArtifact(random_bytes(32), $clock), $clock);
    $token = $manager->issue(oauthRefreshManagerGrant(1_700_086_400), 300);

    expect($manager->rotate($token, 'browser-client', str_repeat('B', 43), 300)->status)->toBe(RefreshTokenRotationStatus::SENDER_MISMATCH)
        ->and($manager->revoke($token))->toBeTrue()
        ->and($manager->rotate($token, 'browser-client', str_repeat('A', 43), 300)->status)->toBe(RefreshTokenRotationStatus::REVOKED);

    $expiring = $manager->issue(oauthRefreshManagerGrant(1_700_086_400, 'authorization-2'), 300);
    $clock->timestamp += 301;
    expect($manager->rotate($expiring, 'browser-client', str_repeat('A', 43), 300)->status)->toBe(RefreshTokenRotationStatus::EXPIRED);

    $revoked = $manager->issue(oauthRefreshManagerGrant(1_700_086_400, 'authorization-3'), 300);
    expect($manager->revokeAuthorization('authorization-3'))->toBe(1)
        ->and($manager->rotate($revoked, 'browser-client', str_repeat('A', 43), 300)->status)->toBe(RefreshTokenRotationStatus::REVOKED);
});

it('maps malformed and absolutely expired refresh credentials to stable lifecycle statuses', function () {
    $clock = oauthRefreshManagerClock(1_700_000_000);
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), oauthRefreshManagerArtifact(random_bytes(32), $clock), $clock);
    expect($manager->rotate('not-a-jwe', 'browser-client', str_repeat('A', 43))->status)->toBe(RefreshTokenRotationStatus::INVALID);

    $token = $manager->issue(oauthRefreshManagerGrant(1_700_000_010), 10);
    $clock->timestamp += 10;
    expect($manager->rotate($token, 'browser-client', str_repeat('A', 43), 10)->status)->toBe(RefreshTokenRotationStatus::EXPIRED);
});
