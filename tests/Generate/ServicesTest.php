<?php

use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;

it('generates secure random values for all generators', function () {
    $random = new RandomBytesGenerator();
    $salt = new SaltGenerator();
    $nonce = new NonceGenerator();
    $keyMaterial = new KeyMaterialGenerator();
    $tokenMaterial = new TokenMaterialGenerator();

    expect(strlen($random->bytes(32)))->toBe(32);
    expect($random->string(40))->toHaveLength(40);
    expect($salt->generate())->not->toBe('');
    expect($nonce->generate())->not->toBe('');
    expect($keyMaterial->generate())->not->toBe('');
    expect($tokenMaterial->generate(48))->toHaveLength(48);
});
