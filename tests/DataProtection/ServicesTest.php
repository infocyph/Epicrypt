<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts string data safely', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new StringProtector();
    $ciphertext = $protector->encrypt('protected data', $key);
    $plaintext = $protector->decrypt($ciphertext, $key);

    expect($plaintext)->toBe('protected data');
});
