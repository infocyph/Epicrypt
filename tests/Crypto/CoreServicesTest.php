<?php

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Mac;
use Infocyph\Epicrypt\Crypto\Signature;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('encrypts and decrypts with AEAD services', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    $cipher = new AeadCipher();

    $ciphertext = $cipher->encrypt('epicrypt-aead', $key, ['aad' => 'meta']);
    $plaintext = $cipher->decrypt($ciphertext, $key, ['aad' => 'meta']);

    expect($ciphertext)->toStartWith('epc1.');
    expect($plaintext)->toBe('epicrypt-aead');
});

it('blocks AEAD encryption when using the legacy-decrypt-only profile', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    $cipher = AeadCipher::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);

    expect(fn () => $cipher->encrypt('epicrypt-aead', $key))
        ->toThrow('AEAD encryption is disabled for the legacy-decrypt-only profile.');
});

it('still decrypts AEAD ciphertext in legacy-decrypt-only mode', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    $modern = AeadCipher::forProfile(SecurityProfile::MODERN);
    $legacyReadOnly = AeadCipher::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);

    $ciphertext = $modern->encrypt('epicrypt-aead', $key, ['aad' => 'meta']);

    expect($legacyReadOnly->decrypt($ciphertext, $key, ['aad' => 'meta']))->toBe('epicrypt-aead');
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
