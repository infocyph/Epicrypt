<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('validates explicit AEAD key and AAD inputs', function () {
    $cipher = new AeadCipher;
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    expect(fn () => $cipher->encryptWithBinaryKey('payload', 'short'))
        ->toThrow(InvalidKeyException::class)
        ->and($cipher->decrypt($cipher->encrypt('payload', $key, 'aad'), $key, 'aad'))
        ->toBe('payload');
});

it('validates explicit AEAD nonces', function () {
    $cipher = new AeadCipher;
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    expect(fn () => $cipher->encryptWithBinaryKey('payload', random_bytes(32), nonce: ''))
        ->toThrow(InvalidNonceException::class);
});
