<?php

use Infocyph\Epicrypt\Crypto\Aead\Decryptor as AeadDecryptor;
use Infocyph\Epicrypt\Crypto\Aead\Encryptor as AeadEncryptor;
use Infocyph\Epicrypt\Crypto\Auth\MacGenerator;
use Infocyph\Epicrypt\Crypto\Auth\MacVerifier;
use Infocyph\Epicrypt\Crypto\Signature\Signer;
use Infocyph\Epicrypt\Crypto\Signature\Verifier;
use Infocyph\Epicrypt\Crypto\Support\KeyPair;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts with AEAD services', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    $encryptor = new AeadEncryptor();
    $decryptor = new AeadDecryptor();

    $ciphertext = $encryptor->encrypt('epicrypt-aead', $key, ['aad' => 'meta']);
    $plaintext = $decryptor->decrypt($ciphertext, $key, ['aad' => 'meta']);

    expect($plaintext)->toBe('epicrypt-aead');
});

it('signs and verifies detached signatures', function () {
    $keys = KeyPair::sodiumSign();

    $signer = new Signer();
    $verifier = new Verifier();

    $signature = $signer->sign('epicrypt-signature', $keys['private']);

    expect($verifier->verify('epicrypt-signature', $signature, $keys['public']))->toBeTrue();
    expect($verifier->verify('tampered', $signature, $keys['public']))->toBeFalse();
});

it('generates and verifies mac tags', function () {
    $generator = new MacGenerator();
    $verifier = new MacVerifier();

    $key = $generator->generateKey();
    $mac = $generator->generate('epicrypt-mac', $key);

    expect($verifier->verify('epicrypt-mac', $mac, $key))->toBeTrue();
    expect($verifier->verify('wrong', $mac, $key))->toBeFalse();
});
