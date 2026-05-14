<?php

use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('validates aead context key and aad types', function () {
    $cipher = new AeadCipher;
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    expect(fn () => $cipher->encrypt('payload', $key, ['key_is_binary' => 'yes']))
        ->toThrow(CryptoException::class);
    expect(fn () => $cipher->encrypt('payload', $key, ['aad' => 123]))
        ->toThrow(CryptoException::class);
});

it('validates aead context nonce type', function () {
    $cipher = new AeadCipher;
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    expect(fn () => $cipher->encrypt('payload', $key, ['nonce' => '']))
        ->toThrow(InvalidNonceException::class);
});
