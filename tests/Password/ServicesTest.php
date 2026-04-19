<?php

use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('generates and verifies password hashes', function () {
    $generator = new PasswordGenerator();
    $password = $generator->generate(16);

    $hasher = new PasswordHasher();
    $hash = $hasher->hashPassword($password);

    expect($hasher->verifyPassword($password, $hash))->toBeTrue();
    expect($hasher->verifyPassword('wrong-password', $hash))->toBeFalse();
});

it('detects password rehash lifecycle state and can produce a replacement hash', function () {
    $password = 'MyStrongPassword!2026';
    $hasher = new PasswordHasher();

    $legacyHash = $hasher->hashPassword($password, [
        'algorithm' => PasswordHashAlgorithm::BCRYPT,
    ]);

    expect($hasher->needsRehash($legacyHash))->toBeTrue();

    $result = $hasher->verifyAndNeedsRehash($password, $legacyHash, [
        'profile' => SecurityProfile::MODERN,
    ]);

    expect($result->verified)->toBeTrue();
    expect($result->needsRehash)->toBeTrue();
    expect($result->rehashedHash)->toBeNull();

    $rehashed = $hasher->verifyAndRehash($password, $legacyHash, [
        'profile' => SecurityProfile::MODERN,
    ]);

    expect($rehashed->verified)->toBeTrue();
    expect($rehashed->needsRehash)->toBeTrue();
    expect($rehashed->rehashedHash)->not->toBeNull();
    expect($hasher->verifyPassword($password, (string) $rehashed->rehashedHash))->toBeTrue();
});

it('wraps and unwraps secrets with master secret', function () {
    $master = (new MasterSecretGenerator())->generate();

    $manager = new WrappedSecretManager();
    $wrapped = $manager->wrap('sensitive-secret', $master);

    expect($wrapped)->toStartWith('eps1.');
    expect($manager->unwrap($wrapped, $master))->toBe('sensitive-secret');

    $segments = explode('.', $wrapped, 3);
    $legacyWrapped = $segments[1] . '.' . $segments[2];
    expect($manager->unwrap($legacyWrapped, $master))->toBe('sensitive-secret');
});

it('supports wrapped secret rollover and rewrap flows', function () {
    $oldMaster = (new MasterSecretGenerator())->generate();
    $newMaster = (new MasterSecretGenerator())->generate();

    $manager = new WrappedSecretManager();
    $wrapped = $manager->wrap('rotated-secret', $oldMaster);

    $rewrapped = $manager->rewrap($wrapped, $oldMaster, $newMaster);
    expect($manager->unwrap($rewrapped, $newMaster))->toBe('rotated-secret');

    $keyRing = new KeyRing([
        'old' => $oldMaster,
        'new' => $newMaster,
    ], 'new');

    $unwrapResult = $manager->unwrapWithAnyKeyResult($wrapped, $keyRing);
    expect($unwrapResult->plaintext)->toBe('rotated-secret');
    expect($unwrapResult->matchedKeyId)->toBe('old');
    expect($unwrapResult->usedFallbackKey)->toBeTrue();

    $rewrappedFromAny = $manager->rewrapWithAnyKey($wrapped, $keyRing, $newMaster);
    expect($manager->unwrapWithAnyKey($rewrappedFromAny, $keyRing))->toBe('rotated-secret');
});
