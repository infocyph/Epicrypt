<?php

use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\Jwks;

it('exports rsa and ec public keys to jwk and resolves by kid', function () {
    $rsa = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    if ($rsa === false) {
        expect(true)->toBeTrue();

        return;
    }
    $ec = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    if ($ec === false) {
        expect(true)->toBeTrue();

        return;
    }

    $rsaDetails = openssl_pkey_get_details($rsa);
    $ecDetails = openssl_pkey_get_details($ec);
    expect($rsaDetails)->toBeArray();
    expect($ecDetails)->toBeArray();

    $jwks = new Jwks();
    $ring = new KeyRing([
        'rsa-key' => $rsaDetails['key'],
        'ec-key' => $ecDetails['key'],
    ], 'rsa-key');

    $set = $jwks->exportFromKeyRing($ring);
    $rsaJwk = $jwks->resolveByKid($set, 'rsa-key');
    $ecJwk = $jwks->resolveByKid($set, 'ec-key');

    expect($set['keys'])->toBeArray();
    expect($rsaJwk['kty'] ?? null)->toBe('RSA');
    expect($ecJwk['kty'] ?? null)->toBe('EC');
});
