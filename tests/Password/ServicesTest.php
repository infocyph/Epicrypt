<?php

use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

it('generates and verifies password hashes', function () {
    $generator = new PasswordGenerator();
    $password = $generator->generate(16);

    $hasher = new PasswordHasher();
    $hash = $hasher->hashPassword($password);

    expect($hasher->verifyPassword($password, $hash))->toBeTrue();
    expect($hasher->verifyPassword('wrong-password', $hash))->toBeFalse();
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
