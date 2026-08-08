<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Password\InvalidPasswordException;
use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\PasswordHashOptions;

it('defaults to Argon2id and preserves rehash detection', function () {
    $hasher = new PasswordHasher();
    $hash = $hasher->hashPassword('correct horse battery staple');
    expect($hash)->toStartWith('$argon2id$')
        ->and($hasher->verifyPassword('correct horse battery staple', $hash))->toBeTrue()
        ->and($hasher->needsRehash($hash))->toBeFalse();
});

it('rejects bcrypt passwords over 72 bytes and invalid hashing options', function () {
    $bcrypt = new PasswordHasher(new PasswordHashOptions(PasswordHashAlgorithm::BCRYPT));
    expect(fn() => $bcrypt->hashPassword(str_repeat('x', 73)))
        ->toThrow(PasswordHashException::class)
        ->and(fn() => new PasswordHashOptions(bcryptCost: 32))
        ->toThrow(PasswordHashException::class);
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
