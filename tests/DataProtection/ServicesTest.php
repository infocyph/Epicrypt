<?php

use Infocyph\Epicrypt\DataProtection\String\StringDecryptor;
use Infocyph\Epicrypt\DataProtection\String\StringEncryptor;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts string data safely', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $encryptor = new StringEncryptor();
    $decryptor = new StringDecryptor();

    $ciphertext = $encryptor->encrypt('protected data', $key);
    $plaintext = $decryptor->decrypt($ciphertext, $key);

    expect($plaintext)->toBe('protected data');
});
