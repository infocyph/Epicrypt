<?php

use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

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
    expect($keyMaterial->forSecretBox())->not->toBe('');
    expect($keyMaterial->forPurpose(KeyPurpose::MASTER_SECRET, SecurityProfile::MODERN))->not->toBe('');
    expect($tokenMaterial->generate(48))->toHaveLength(48);
});

it('derives keys using hkdf, password derivation, and deterministic subkeys', function () {
    $deriver = new KeyDeriver();
    $generator = new KeyMaterialGenerator();
    $salt = (new SaltGenerator())->generate(SODIUM_CRYPTO_PWHASH_SALTBYTES);

    $hkdf = $deriver->hkdf($generator->generate(32), 32, [
        'info' => 'epicrypt:test',
        'salt' => $generator->generate(16),
    ]);

    $passwordKey = $deriver->deriveFromPassword('MyStrongPassword!2026', $salt, 32, [
        'profile' => SecurityProfile::MODERN,
    ]);

    $rootKey = $generator->generate(SODIUM_CRYPTO_KDF_KEYBYTES);
    $subkeyA = $deriver->subkey($rootKey, 1, 32, ['context' => 'EPICTST1']);
    $subkeyB = $deriver->subkey($rootKey, 1, 32, ['context' => 'EPICTST1']);
    $subkeyC = $deriver->subkey($rootKey, 2, 32, ['context' => 'EPICTST1']);

    expect($hkdf)->not->toBe('');
    expect($passwordKey)->not->toBe('');
    expect($subkeyA)->toBe($subkeyB);
    expect($subkeyA)->not->toBe($subkeyC);
});
