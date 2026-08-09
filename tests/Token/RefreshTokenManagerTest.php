<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenManager;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;
use Psr\Clock\ClockInterface;

function refreshTokenClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@'.$this->timestamp);
        }
    };
}

function refreshTokenGrant(int $expiresAt, string $id = 'grant-1'): RefreshTokenGrant
{
    return new RefreshTokenGrant(
        id: $id,
        subject: 'user-42',
        clientId: 'browser-client',
        audiences: ['orders-api'],
        scopes: ['orders:read', 'orders:write'],
        expiresAt: $expiresAt,
        dpopKeyThumbprint: str_repeat('A', 43),
    );
}

it('rotates refresh tokens once and revokes the family when an ancestor is reused', function () {
    $clock = refreshTokenClock(1_700_000_000);
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), clock: $clock);
    $grant = refreshTokenGrant(1_700_086_400);
    $original = $manager->issue($grant, 3_600);

    $clientMismatch = $manager->rotate($original, 'other-client', str_repeat('A', 43), 3_600);
    expect($clientMismatch->status)->toBe(RefreshTokenRotationStatus::CLIENT_MISMATCH);

    $scopeMismatch = $manager->rotate(
        $original,
        'browser-client',
        str_repeat('A', 43),
        3_600,
        ['orders:delete'],
    );
    expect($scopeMismatch->status)->toBe(RefreshTokenRotationStatus::SCOPE_MISMATCH);

    $rotated = $manager->rotate(
        $original,
        'browser-client',
        str_repeat('A', 43),
        3_600,
        ['orders:read'],
    );
    expect($rotated->rotated)->toBeTrue()
        ->and($rotated->token)->not->toBeNull()
        ->and($rotated->token)->not->toBe($original)
        ->and($rotated->grant?->scopes)->toBe(['orders:read']);

    $reused = $manager->rotate($original, 'browser-client', str_repeat('A', 43), 3_600);
    expect($reused->status)->toBe(RefreshTokenRotationStatus::REUSED);

    $familyRevoked = $manager->rotate($rotated->token ?? '', 'browser-client', str_repeat('A', 43), 3_600);
    expect($familyRevoked->status)->toBe(RefreshTokenRotationStatus::REVOKED);
});

it('enforces sender binding, idle expiration, explicit revocation and grant revocation', function () {
    $clock = refreshTokenClock(1_700_000_000);
    $store = new InMemoryRefreshTokenStore();
    $manager = new RefreshTokenManager($store, clock: $clock);
    $grant = refreshTokenGrant(1_700_086_400);
    $senderBound = $manager->issue($grant, 300);

    expect($manager->rotate($senderBound, 'browser-client', str_repeat('B', 43), 300)->status)
        ->toBe(RefreshTokenRotationStatus::SENDER_MISMATCH)
        ->and($manager->revoke($senderBound))->toBeTrue()
        ->and($manager->rotate($senderBound, 'browser-client', str_repeat('A', 43), 300)->status)
        ->toBe(RefreshTokenRotationStatus::REVOKED);

    $expiring = $manager->issue(refreshTokenGrant(1_700_086_400, 'grant-2'), 300);
    $clock->timestamp += 301;
    expect($manager->rotate($expiring, 'browser-client', str_repeat('A', 43), 300)->status)
        ->toBe(RefreshTokenRotationStatus::EXPIRED);

    $revokedByGrant = $manager->issue(refreshTokenGrant(1_700_086_400, 'grant-3'), 300);
    expect($manager->revokeGrant('grant-3'))->toBe(1)
        ->and($manager->rotate($revokedByGrant, 'browser-client', str_repeat('A', 43), 300)->status)
        ->toBe(RefreshTokenRotationStatus::REVOKED);
});

it('rejects unsafe refresh-token policy input without touching storage', function () {
    $manager = new RefreshTokenManager(new InMemoryRefreshTokenStore(), clock: refreshTokenClock(1_700_000_000));

    expect($manager->rotate('short', 'browser-client')->status)->toBe(RefreshTokenRotationStatus::INVALID)
        ->and(fn() => $manager->issue(refreshTokenGrant(1_699_999_999)))->toThrow(ConfigurationException::class)
        ->and(fn() => $manager->rotate(str_repeat('A', 48), '', null))->toThrow(ConfigurationException::class)
        ->and(fn() => $manager->rotate(str_repeat('A', 48), 'browser-client', 'weak-thumbprint'))
        ->toThrow(ConfigurationException::class);
});
