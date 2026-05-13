<?php

use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
use Infocyph\Epicrypt\Password\NullCompromisedPasswordChecker;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\PasswordPolicyValidator;
use Infocyph\Epicrypt\Password\PasswordStrength;
use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('generates and verifies password hashes', function () {
    $generator = new PasswordGenerator;
    $password = $generator->generate(16);

    $hasher = new PasswordHasher;
    $hash = $hasher->hashPassword($password);

    expect($hasher->verifyPassword($password, $hash))->toBeTrue();
    expect($hasher->verifyPassword('wrong-password', $hash))->toBeFalse();
});

it('detects password rehash lifecycle state and can produce a replacement hash', function () {
    $password = 'MyStrongPassword!2026';
    $hasher = new PasswordHasher;

    $previousHash = $hasher->hashPassword($password, [
        'algorithm' => PasswordHashAlgorithm::BCRYPT,
    ]);

    expect($hasher->needsRehash($previousHash))->toBeTrue();

    $result = $hasher->verifyAndNeedsRehash($password, $previousHash, [
        'profile' => SecurityProfile::MODERN,
    ]);

    expect($result->verified)->toBeTrue();
    expect($result->needsRehash)->toBeTrue();
    expect($result->rehashedHash)->toBeNull();

    $rehashed = $hasher->verifyAndRehash($password, $previousHash, [
        'profile' => SecurityProfile::MODERN,
    ]);

    expect($rehashed->verified)->toBeTrue();
    expect($rehashed->needsRehash)->toBeTrue();
    expect($rehashed->rehashedHash)->not->toBeNull();
    expect($hasher->verifyPassword($password, (string) $rehashed->rehashedHash))->toBeTrue();
});

it('wraps and unwraps secrets with master secret', function () {
    $master = (new MasterSecretGenerator)->generate();

    $manager = new WrappedSecretManager;
    $wrapped = $manager->wrap('sensitive-secret', $master);
    $segments = explode('.', $wrapped);

    expect($wrapped)->toStartWith('eps1.');
    expect($segments)->toHaveCount(5);
    expect($segments[1])->toBe('secretbox');
    expect($segments[2])->toBe('_');
    expect($manager->unwrap($wrapped, $master))->toBe('sensitive-secret');

    $unversionedWrapped = implode('.', array_slice($segments, 1));
    expect($manager->unwrap($unversionedWrapped, $master))->toBe('sensitive-secret');
});

it('supports wrapped secret rollover and rewrap flows', function () {
    $oldMaster = (new MasterSecretGenerator)->generate();
    $newMaster = (new MasterSecretGenerator)->generate();

    $manager = new WrappedSecretManager;
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

it('embeds and resolves key ids for wrapped secrets with key rings', function () {
    $oldMaster = (new MasterSecretGenerator)->generate();
    $newMaster = (new MasterSecretGenerator)->generate();

    $keyRing = new KeyRing([
        'old' => $oldMaster,
        'new' => $newMaster,
    ], 'new');

    $manager = new WrappedSecretManager;
    $wrapped = $manager->wrapWithKeyRing('rotated-secret', $keyRing);
    $segments = explode('.', $wrapped);
    $result = $manager->unwrapWithKeyRingResult($wrapped, $keyRing);

    expect($segments[2])->toBe('new');
    expect($result->plaintext)->toBe('rotated-secret');
    expect($result->matchedKeyId)->toBe('new');
    expect($result->usedFallbackKey)->toBeFalse();
});

it('does not fallback for wrapped secrets when key id is present but key is wrong', function () {
    $oldMaster = (new MasterSecretGenerator)->generate();
    $wrongNewMaster = (new MasterSecretGenerator)->generate();

    $keyRing = new KeyRing([
        'old' => $oldMaster,
        'new' => $wrongNewMaster,
    ], 'new');

    $manager = new WrappedSecretManager;
    $wrapped = $manager->wrap('rotated-secret', $oldMaster, false, 'new');

    expect(fn() => $manager->unwrapWithKeyRingResult($wrapped, $keyRing))
        ->toThrow(SecretProtectionException::class);
});

it('supports algorithm-specific password hash options', function () {
    $hasher = new PasswordHasher;
    $password = 'MyStrongPassword!2026';

    $bcryptHash = $hasher->hashPassword($password, [
        'algorithm' => PasswordHashAlgorithm::BCRYPT,
        'cost' => 10,
    ]);
    $argonHash = $hasher->hashPassword($password, [
        'algorithm' => PasswordHashAlgorithm::ARGON2ID,
        'memory_cost' => 131072,
        'time_cost' => 4,
        'threads' => 2,
    ]);

    expect($hasher->verifyPassword($password, $bcryptHash))->toBeTrue();
    expect($hasher->verifyPassword($password, $argonHash))->toBeTrue();
});

it('validates password policies and returns score and violations', function () {
    $validator = new PasswordPolicyValidator;
    $policy = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true, includeAmbiguous: false);

    $invalid = $validator->validate('weakpass', $policy);
    $valid = $validator->validate('Str0ng!Password#2026', $policy);

    expect($invalid->valid)->toBeFalse();
    expect($invalid->violations)->toContain('too_short');
    expect($invalid->violations)->toContain('missing_upper');
    expect($invalid->violations)->toContain('missing_digit');
    expect($invalid->violations)->toContain('missing_symbol');
    expect($valid->valid)->toBeTrue();
    expect($valid->score)->toBeGreaterThan(0);
});

it('applies improved password strength penalties', function () {
    $strength = new PasswordStrength;

    $weak = $strength->score('Password1234');
    $strong = $strength->score('V3ry$trong-Passw0rd!2026', ['username' => 'alice', 'email' => 'alice@example.com']);
    $identityPenalty = $strength->score('alice-Password!2026', ['username' => 'alice']);

    expect($strong)->toBeGreaterThan($weak);
    expect($identityPenalty)->toBeLessThan($strong);
});

it('provides a null compromised password checker implementation', function () {
    $checker = new NullCompromisedPasswordChecker;

    expect($checker->isCompromised('any-password'))->toBeFalse();
});
