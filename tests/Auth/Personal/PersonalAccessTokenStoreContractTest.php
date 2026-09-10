<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenRecord;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Tests\Support\InMemoryPersonalAccessTokenStore;

it('stores only personal-token metadata and provides bounded deterministic listing', function () {
    $store = new InMemoryPersonalAccessTokenStore();
    $older = new PersonalAccessTokenRecord(
        tokenId: Base64Url::encode(str_repeat('A', 24)),
        subject: 'user-1',
        name: 'older',
        abilities: ['orders:read'],
        createdAt: 1_700_000_000,
    );
    $newer = new PersonalAccessTokenRecord(
        tokenId: Base64Url::encode(str_repeat('B', 24)),
        subject: 'user-1',
        name: 'newer',
        abilities: ['orders:read', 'orders:write'],
        createdAt: 1_700_000_100,
    );

    expect($store->create($older))->toBeTrue()
        ->and($store->create($newer))->toBeTrue()
        ->and($store->create($newer))->toBeFalse()
        ->and(array_map(static fn(PersonalAccessTokenRecord $record): string => $record->name, $store->listForSubject('user-1')))
        ->toBe(['newer', 'older']);
});

it('revokes personal tokens idempotently and revoke-all respects subject boundaries', function () {
    $store = new InMemoryPersonalAccessTokenStore();
    $one = new PersonalAccessTokenRecord(
        Base64Url::encode(str_repeat('C', 24)),
        'user-1',
        'one',
        ['orders:read'],
        1_700_000_000,
    );
    $two = new PersonalAccessTokenRecord(
        Base64Url::encode(str_repeat('D', 24)),
        'user-1',
        'two',
        ['orders:write'],
        1_700_000_000,
    );
    $other = new PersonalAccessTokenRecord(
        Base64Url::encode(str_repeat('E', 24)),
        'user-2',
        'other',
        ['orders:read'],
        1_700_000_000,
    );
    foreach ([$one, $two, $other] as $record) {
        $store->create($record);
    }

    $revoked = $store->revoke($one->tokenId, 'user-1', 1_700_000_100);
    $again = $store->revoke($one->tokenId, 'user-1', 1_700_000_200);
    $remaining = $store->revokeAll('user-1', 1_700_000_300);

    expect($revoked?->revokedAt)->toBe(1_700_000_100)
        ->and($again?->revokedAt)->toBe(1_700_000_100)
        ->and($remaining)->toBe(1)
        ->and($store->find($two->tokenId)?->isActive(1_700_000_300))->toBeFalse()
        ->and($store->find($other->tokenId)?->isActive(1_700_000_300))->toBeTrue()
        ->and($store->revoke($other->tokenId, 'user-1', 1_700_000_400))->toBeNull();
});
