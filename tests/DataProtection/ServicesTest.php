<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts string data safely', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new StringProtector();
    $ciphertext = $protector->encrypt('protected data', $key);
    $plaintext = $protector->decrypt($ciphertext, $key);

    expect($ciphertext)->toStartWith('epc1.');
    expect($plaintext)->toBe('protected data');
});

it('encrypts and decrypts versioned envelopes', function () {
    $masterKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new EnvelopeProtector();
    $envelope = $protector->encrypt('enveloped data', $masterKey);
    $encoded = $protector->encodeEnvelope($envelope);
    $plaintext = $protector->decrypt($encoded, $masterKey);

    expect($envelope['v'])->toBe(1);
    expect($envelope['alg'])->toBe('secretbox');
    expect($plaintext)->toBe('enveloped data');
});
