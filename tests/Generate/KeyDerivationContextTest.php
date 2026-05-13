<?php

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDerivationContext;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('derives keys using typed key derivation context objects', function () {
    $deriver = new KeyDeriver;
    $generator = new KeyMaterialGenerator;

    $hkdf = $deriver->hkdf(
        $generator->generate(32),
        32,
        new KeyDerivationContext(
            info: 'typed-context',
            salt: $generator->generate(16),
            profile: SecurityProfile::MODERN,
        ),
    );

    $password = $deriver->deriveFromPassword(
        'MyStrongPassword!2026',
        (new SaltGenerator())->generate(SODIUM_CRYPTO_PWHASH_SALTBYTES),
        32,
        new KeyDerivationContext(profile: SecurityProfile::MODERN),
    );

    $rootKey = $generator->generate(SODIUM_CRYPTO_KDF_KEYBYTES);
    $subkey = $deriver->subkey(
        $rootKey,
        7,
        32,
        new KeyDerivationContext(sodiumContext: 'EPICTST1'),
    );

    expect($hkdf)->not->toBe('');
    expect($password)->not->toBe('');
    expect($subkey)->not->toBe('');
});

it('validates typed key derivation context input values', function () {
    expect(fn() => KeyDerivationContext::fromArray([
        'salt_is_binary' => 'yes',
    ]))->toThrow(ConfigurationException::class);

    expect(fn() => KeyDerivationContext::fromArray([
        'profile' => 'modern',
    ]))->toThrow(ConfigurationException::class);
});

