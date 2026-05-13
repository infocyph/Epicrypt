<?php

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

it('decodes secret-box keys from base64url and binary forms', function () {
    $binary = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $encoded = Base64Url::encode($binary);

    expect(BinaryKey::secretBoxKey($encoded, false))->toBe($binary);
    expect(BinaryKey::secretBoxKey($binary, true))->toBe($binary);
});

it('rejects invalid key lengths through typed helpers', function () {
    expect(fn() => BinaryKey::macKey('short', true))->toThrow(InvalidKeyException::class);
    expect(fn() => BinaryKey::aeadKey('short', true, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES))
        ->toThrow(InvalidKeyException::class);
});
