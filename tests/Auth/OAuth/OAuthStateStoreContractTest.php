<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenStatusRecord;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRecord;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthAccessTokenStatusStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthAuthorizationStore;

it('keeps approved OAuth authorization state authoritative and revocation idempotent', function () {
    $record = new OAuthAuthorizationRecord(
        authorizationId: 'authorization-1',
        subject: 'user-1',
        clientId: 'browser-client',
        scopes: ['orders:read', 'orders:write'],
        audiences: ['orders-api'],
        authorizedAt: 1_700_000_000,
        expiresAt: 1_700_003_600,
    );
    $store = new InMemoryOAuthAuthorizationStore();

    expect($store->create($record))->toBeTrue()
        ->and($store->create($record))->toBeFalse()
        ->and($store->find('authorization-1')?->isActive(1_700_000_100))->toBeTrue();

    $revoked = $store->revoke('authorization-1', 1_700_000_200);
    $again = $store->revoke('authorization-1', 1_700_000_300);

    expect($revoked?->isActive(1_700_000_200))->toBeFalse()
        ->and($again?->revokedAt)->toBe(1_700_000_200)
        ->and($store->revoke('missing', 1_700_000_200))->toBeNull();
});

it('stores access-token status by issuer and jti without a raw jwt', function () {
    $record = new OAuthAccessTokenStatusRecord(
        issuer: 'https://auth.example.com',
        tokenId: 'access-jti-1',
        subject: 'user-1',
        clientId: 'browser-client',
        expiresAt: 1_700_000_600,
        authorizationId: 'authorization-1',
    );
    $store = new InMemoryOAuthAccessTokenStatusStore();

    expect($store->create($record))->toBeTrue()
        ->and($store->create($record))->toBeFalse()
        ->and($store->find('https://auth.example.com', 'access-jti-1')?->isActive(1_700_000_100))->toBeTrue()
        ->and($store->find('https://other.example.com', 'access-jti-1'))->toBeNull();

    $revoked = $store->revoke('https://auth.example.com', 'access-jti-1', 1_700_000_200);
    $again = $store->revoke('https://auth.example.com', 'access-jti-1', 1_700_000_300);

    expect($revoked?->isActive(1_700_000_200))->toBeFalse()
        ->and($again?->revokedAt)->toBe(1_700_000_200);
});
