<?php

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Mac;
use Infocyph\Epicrypt\Crypto\Signature;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts with AEAD services', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    $cipher = new AeadCipher();

    $ciphertext = $cipher->encrypt('epicrypt-aead', $key, ['aad' => 'meta']);
    $plaintext = $cipher->decrypt($ciphertext, $key, ['aad' => 'meta']);

    expect($ciphertext)->toStartWith('epc1.');
    expect($plaintext)->toBe('epicrypt-aead');
});

it('signs and verifies detached signatures', function () {
    $keys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);

    $signatureService = new Signature();
    $signature = $signatureService->sign('epicrypt-signature', $keys['private']);

    expect($signatureService->verify('epicrypt-signature', $signature, $keys['public']))->toBeTrue();
    expect($signatureService->verify('tampered', $signature, $keys['public']))->toBeFalse();
});

it('generates and verifies mac tags', function () {
    $macService = new Mac();
    $key = $macService->generateKey();
    $mac = $macService->generate('epicrypt-mac', $key);

    expect($macService->verify('epicrypt-mac', $mac, $key))->toBeTrue();
    expect($macService->verify('wrong', $mac, $key))->toBeFalse();
});
