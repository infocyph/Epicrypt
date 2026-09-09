<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenManager;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenPolicy;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenValidationStatus;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenWildcardPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryPersonalAccessTokenStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryPersonalAccessTokenUsageStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Psr\Clock\ClockInterface;

function patClock(int $timestamp = 1_700_000_000): object
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function patSigningKeys(KeyPurpose $purpose = KeyPurpose::API_PERSONAL_TOKEN_SIGNING): AsymmetricSigningKeySet
{
    $issuer = 'https://issuer.example.test';
    $pair = sodium_crypto_sign_keypair();
    $private = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $ring = new KeyRing([
        new KeyRingEntry('pat-active', $public, KeyStatus::ACTIVE, $purpose, 'EdDSA', issuer: $issuer),
    ]);

    return new AsymmetricSigningKeySet(
        issuer: $issuer,
        activeKeyId: 'pat-active',
        privateKey: $private,
        publicKeys: $ring,
        algorithm: AsymmetricJwtAlgorithm::EDDSA,
        purpose: $purpose,
    );
}

it('issues verifies lists and revokes stateful pat jwt credentials', function () {
    $clock = patClock();
    $store = new InMemoryPersonalAccessTokenStore();
    $manager = new PersonalAccessTokenManager(
        patSigningKeys(),
        $store,
        new PersonalAccessTokenPolicy('https://api.example.test'),
        clock: $clock,
    );

    $issue = $manager->issue('user-1', 'cli', ['repo:read', 'repo:write']);
    $verified = $manager->verify($issue->token);

    expect(substr_count($issue->token, '.'))->toBe(2)
        ->and($verified->status)->toBe(PersonalAccessTokenValidationStatus::VALID)
        ->and($verified->allows('repo:read'))->toBeTrue()
        ->and($verified->allows('admin'))->toBeFalse()
        ->and($manager->list('user-1'))->toHaveCount(1)
        ->and($store->find($issue->record->tokenId)?->tokenId)->toBe($issue->record->tokenId);

    $manager->revoke($issue->record->tokenId, 'user-1');
    expect($manager->verify($issue->token)->status)->toBe(PersonalAccessTokenValidationStatus::INACTIVE);
});

it('requires an explicit wildcard policy and applies wildcard only when enabled', function () {
    $clock = patClock();
    $keys = patSigningKeys();

    $strict = new PersonalAccessTokenManager(
        $keys,
        new InMemoryPersonalAccessTokenStore(),
        new PersonalAccessTokenPolicy('https://api.example.test'),
        clock: $clock,
    );
    expect(fn () => $strict->issue('user-1', 'strict', ['*']))
        ->toThrow(ConfigurationException::class);

    $wild = new PersonalAccessTokenManager(
        $keys,
        new InMemoryPersonalAccessTokenStore(),
        new PersonalAccessTokenPolicy(
            'https://api.example.test',
            wildcardPolicy: PersonalAccessTokenWildcardPolicy::STAR,
        ),
        clock: $clock,
    );
    $issue = $wild->issue('user-1', 'wildcard', ['*']);
    expect($wild->verify($issue->token)->allows('anything:bounded'))->toBeTrue();
});

it('uses bounded default expiry and rejects caller expiry beyond policy', function () {
    $clock = patClock();
    $manager = new PersonalAccessTokenManager(
        patSigningKeys(),
        new InMemoryPersonalAccessTokenStore(),
        new PersonalAccessTokenPolicy(
            audience: 'https://api.example.test',
            defaultLifetimeSeconds: 60,
            maximumLifetimeSeconds: 300,
        ),
        clock: $clock,
    );

    $issue = $manager->issue('user-1', 'short', ['read']);
    expect($issue->record->expiresAt)->toBe(1_700_000_060);

    $clock->timestamp = 1_700_000_060;
    expect($manager->verify($issue->token)->accepted())->toBeFalse();

    $clock->timestamp = 1_700_000_000;
    expect(fn () => $manager->issue('user-1', 'too-long', ['read'], 1_700_000_301))
        ->toThrow(ConfigurationException::class);
});

it('revokes all tokens for one subject without crossing subject boundaries', function () {
    $clock = patClock();
    $manager = new PersonalAccessTokenManager(
        patSigningKeys(),
        new InMemoryPersonalAccessTokenStore(),
        new PersonalAccessTokenPolicy('https://api.example.test'),
        clock: $clock,
    );

    $one = $manager->issue('user-1', 'one', ['read']);
    $two = $manager->issue('user-1', 'two', ['write']);
    $other = $manager->issue('user-2', 'other', ['read']);

    expect($manager->revokeAll('user-1'))->toBe(2)
        ->and($manager->verify($one->token)->accepted())->toBeFalse()
        ->and($manager->verify($two->token)->accepted())->toBeFalse()
        ->and($manager->verify($other->token)->accepted())->toBeTrue();
});

it('enforces audience and signing-purpose isolation', function () {
    $clock = patClock();
    $keys = patSigningKeys();
    $store = new InMemoryPersonalAccessTokenStore();
    $manager = new PersonalAccessTokenManager(
        $keys,
        $store,
        new PersonalAccessTokenPolicy('https://api.example.test'),
        clock: $clock,
    );
    $issue = $manager->issue('user-1', 'api', ['read']);

    $wrongAudience = new PersonalAccessTokenManager(
        $keys,
        $store,
        new PersonalAccessTokenPolicy('https://other.example.test'),
        clock: $clock,
    );
    expect($wrongAudience->verify($issue->token)->accepted())->toBeFalse()
        ->and(fn () => new PersonalAccessTokenManager(
            patSigningKeys(KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING),
            new InMemoryPersonalAccessTokenStore(),
            new PersonalAccessTokenPolicy('https://api.example.test'),
            clock: $clock,
        ))->toThrow(ConfigurationException::class);
});

it('coalesces optional last-used writes across fibers and persistent verification', function () {
    $clock = patClock();
    $usage = new InMemoryPersonalAccessTokenUsageStore();
    $manager = new PersonalAccessTokenManager(
        patSigningKeys(),
        new InMemoryPersonalAccessTokenStore(),
        new PersonalAccessTokenPolicy(
            audience: 'https://api.example.test',
            lastUsedWriteIntervalSeconds: 60,
        ),
        $usage,
        $clock,
    );
    $issue = $manager->issue('user-1', 'worker', ['read']);

    $fibers = [
        new Fiber(fn () => $manager->verify($issue->token)),
        new Fiber(fn () => $manager->verify($issue->token)),
    ];
    foreach ($fibers as $fiber) {
        $result = $fiber->start();
        expect($result)->toBeNull();
    }
    expect($usage->writes)->toBe(1);

    for ($i = 0; $i < 50; $i++) {
        expect($manager->verify($issue->token)->accepted())->toBeTrue();
    }
    expect($usage->writes)->toBe(1);

    $clock->timestamp += 60;
    expect($manager->verify($issue->token)->accepted())->toBeTrue()
        ->and($usage->writes)->toBe(2);
});
