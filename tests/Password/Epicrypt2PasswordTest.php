<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Password\InvalidPasswordException;
use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\PasswordHashOptions;
use Infocyph\Epicrypt\Password\PasswordPolicyValidator;
use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;
use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;

it('defaults to Argon2id and preserves rehash detection', function () {
    $hasher = new PasswordHasher();
    $hash = $hasher->hashPassword('correct horse battery staple');
    expect($hash)->toStartWith('$argon2id$')
        ->and($hasher->verifyPassword('correct horse battery staple', $hash))->toBeTrue()
        ->and($hasher->needsRehash($hash))->toBeFalse();
});

it('rejects bcrypt passwords over 72 bytes and invalid hashing options', function () {
    $bcrypt = new PasswordHasher(new PasswordHashOptions(PasswordHashAlgorithm::BCRYPT));
    $seventyTwo = str_repeat('x', 72);
    expect($bcrypt->verifyPassword($seventyTwo, $bcrypt->hashPassword($seventyTwo)))->toBeTrue()
        ->and(fn() => $bcrypt->hashPassword(str_repeat('x', 73)))
        ->toThrow(PasswordHashException::class)
        ->and(fn() => new PasswordHashOptions(PasswordHashAlgorithm::BCRYPT, bcryptCost: 32))
        ->toThrow(PasswordHashException::class);

    expect(new PasswordHashOptions(PasswordHashAlgorithm::BCRYPT, memoryCost: 1))->toBeInstanceOf(PasswordHashOptions::class)
        ->and(new PasswordHashOptions(PasswordHashAlgorithm::ARGON2ID, bcryptCost: 32))->toBeInstanceOf(PasswordHashOptions::class);
});

it('supports the curated password hashing algorithms', function () {
    foreach (PasswordHashAlgorithm::cases() as $algorithm) {
        $hasher = new PasswordHasher(new PasswordHashOptions($algorithm));
        $hash = $hasher->hashPassword('correct horse battery staple');

        expect($hasher->verifyPassword('correct horse battery staple', $hash))->toBeTrue();
    }
});

it('generates exactly the requested byte length and rejects impossible policy', function () {
    $generator = new PasswordGenerator();
    expect(strlen($generator->generate(24)))->toBe(24)
        ->and(fn() => $generator->generate(3, new PasswordPolicy(minLength: 1)))
        ->toThrow(InvalidPasswordException::class);
});

it('uses the exact shared ASCII ambiguous-character policy', function () {
    expect(PasswordPolicy::AMBIGUOUS_CHARACTERS)->toBe('0O1IlL');
    $policy = new PasswordPolicy(minLength: 8, includeAmbiguous: false);
    $password = new PasswordGenerator()->generate(128, $policy);

    expect(strpbrk($password, PasswordPolicy::AMBIGUOUS_CHARACTERS))->toBeFalse();
    foreach (str_split(PasswordPolicy::AMBIGUOUS_CHARACTERS) as $ambiguous) {
        expect(new PasswordPolicyValidator()->validate('Aa2!xxxx'.$ambiguous, $policy)->valid)->toBeFalse();
    }
});

it('serializes and wraps recoverable secrets with explicit key formats and exact KeyRing resolution', function () {
    $serializer = new SecureSecretSerializer();
    $manager = new WrappedSecretManager();
    $generator = new KeyMaterialGenerator();
    $old = $generator->forMasterSecret();
    $new = $generator->forMasterSecret();
    $serialized = $serializer->serialize(['provider' => 'payments', 'api_key' => 'secret']);
    $wrapped = $manager->wrap($serialized, $old, 'wrap-old');
    $ring = new KeyRing([
        new KeyRingEntry('wrap-new', $new, KeyStatus::ACTIVE, KeyPurpose::SECRET_WRAPPING, 'secretbox'),
        new KeyRingEntry('wrap-old', $old, KeyStatus::FALLBACK, KeyPurpose::SECRET_WRAPPING, 'secretbox'),
    ]);

    $result = $manager->unwrapWithKeyRingResult($wrapped, $ring);
    expect($serializer->deserialize($result->plaintext))->toBe(['provider' => 'payments', 'api_key' => 'secret'])
        ->and($result->matchedKeyId)->toBe('wrap-old')
        ->and($result->usedFallbackKey)->toBeTrue()
        ->and(fn () => $manager->unwrap($wrapped, $new))->toThrow(SecretProtectionException::class)
        ->and(fn () => $manager->unwrapWithKeyRing($manager->wrap('value', $old), $ring))
        ->toThrow(SecretProtectionException::class);

    $binary = random_bytes(32);
    $binaryWrapped = $manager->wrapWithBinaryKey('raw-key-value', $binary);
    expect($manager->unwrapWithBinaryKey($binaryWrapped, $binary))->toBe('raw-key-value');
});