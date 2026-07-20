<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

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

    $jwks = new Jwks;
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

it('imports jwk to pem and verifies jwt using jwks kid resolution', function () {
    $rsa = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    if ($rsa === false) {
        expect(true)->toBeTrue();

        return;
    }

    $exported = openssl_pkey_export($rsa, $privatePem);
    expect($exported)->toBeTrue();
    expect($privatePem)->toBeString();

    $details = openssl_pkey_get_details($rsa);
    expect($details)->toBeArray();
    $publicPem = $details['key'] ?? null;
    expect($publicPem)->toBeString();

    $jwks = new Jwks;
    $jwk = $jwks->exportPublicKeyToJwk($publicPem, 'rsa-signing');
    $importedPem = $jwks->importPublicKeyFromJwk($jwk);
    expect(openssl_pkey_get_public($importedPem))->not->toBeFalse();

    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 300,
        'kid' => 'rsa-signing',
    ];

    $issuer = new AsymmetricJwt;
    $token = $issuer->encode($claims, $privatePem);

    $verifier = new AsymmetricJwt(
        null,
        expectedClaims: new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );

    $result = $verifier->decodeFromJwksResult($token, ['keys' => [$jwk]]);
    expect($result->verified)->toBeTrue();
    expect($result->matchedKeyId)->toBe('rsa-signing');
});
