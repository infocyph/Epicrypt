<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Psr\Clock\ClockInterface;

it('enforces status, time, purpose, algorithm, and issuer for every resolution', function () {
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@2000');
        }
    };
    $ring = new KeyRing([
        new KeyRingEntry('active', 'key-a', KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'HS512', 1900, 2100, 'issuer'),
        new KeyRingEntry('fallback', 'key-b', KeyStatus::FALLBACK, KeyPurpose::JWT_SIGNING, 'HS512', 1900, 2100, 'issuer'),
        new KeyRingEntry('future', 'key-c', KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'HS512', 2100, null, 'issuer'),
        new KeyRingEntry('expired', 'key-d', KeyStatus::FALLBACK, KeyPurpose::JWT_SIGNING, 'HS512', null, 2000, 'issuer'),
        new KeyRingEntry('retired', 'key-e', KeyStatus::RETIRED, KeyPurpose::JWT_SIGNING, 'HS512', issuer: 'issuer'),
        new KeyRingEntry('disabled', 'key-f', KeyStatus::DISABLED, KeyPurpose::JWT_SIGNING, 'HS512', issuer: 'issuer'),
    ], $clock);

    expect($ring->activeForWrite(KeyPurpose::JWT_SIGNING, 'HS512', 'issuer')->id)->toBe('active')
        ->and(array_map(static fn(KeyRingEntry $entry): string => $entry->id, $ring->readCandidates(KeyPurpose::JWT_SIGNING, 'HS512', 'issuer')))
        ->toBe(['active', 'fallback'])
        ->and($ring->resolveForVerification('active', KeyPurpose::JWT_SIGNING, 'HS256', 'issuer'))->toBeNull()
        ->and($ring->resolveForVerification('active', KeyPurpose::JWT_SIGNING, 'HS512', 'other'))->toBeNull()
        ->and($ring->resolveForVerification('retired', KeyPurpose::JWT_SIGNING, 'HS512', 'issuer'))->toBeNull()
        ->and($ring->resolveForVerification('disabled', KeyPurpose::JWT_SIGNING, 'HS512', 'issuer'))->toBeNull()
        ->and($ring->resolveForVerification('active', KeyPurpose::DATA_PROTECTION, 'HS512', 'issuer'))->toBeNull();
});

it('rejects ambiguous active write keys and duplicate ids', function () {
    $entry = new KeyRingEntry('same', 'key', KeyStatus::ACTIVE, KeyPurpose::DATA_PROTECTION, 'alg');
    expect(fn() => new KeyRing([$entry, $entry]))->toThrow(ConfigurationException::class);
});
