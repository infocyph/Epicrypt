<?php

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

it('decodes secret-box keys from base64url and binary forms', function () {
    $binary = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $encoded = Base64Url::encode($binary);

    expect(BinaryKey::fixedLength($encoded, false, SODIUM_CRYPTO_SECRETBOX_KEYBYTES))->toBe($binary);
    expect(BinaryKey::fixedLength($binary, true, SODIUM_CRYPTO_SECRETBOX_KEYBYTES))->toBe($binary);
});

it('rejects invalid key lengths through typed helpers', function () {
    expect(fn () => BinaryKey::fixedLength('short', true, SODIUM_CRYPTO_AUTH_KEYBYTES, 'MAC key'))->toThrow(InvalidKeyException::class);
    expect(fn () => BinaryKey::fixedLength('short', true, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 'AEAD key'))
        ->toThrow(InvalidKeyException::class);
});
