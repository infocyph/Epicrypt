<?php

use Infocyph\Epicrypt\JWT\Asymmetric;

beforeEach(function () {
    $resource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);

    expect($resource)->not->toBeFalse();
    openssl_pkey_export($resource, $privateKey);

    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();
    expect($details)->toHaveKey('key');

    $this->privateKey = $privateKey;
    $this->publicKey = $details['key'];
});

it('encodes and decodes an asymmetric JWT with private/public key pair', function () {
    $issuer = new Asymmetric($this->privateKey);
    $issuer->registerClaims('issuer-rsa', 'audience-rsa', 'subject-rsa', 'token-rsa');
    $now = time();
    $issuer->registerTime($now, $now + 600);
    $token = $issuer->encode(['scope' => 'write']);

    $verifier = new Asymmetric($this->publicKey);
    $verifier->registerClaims('issuer-rsa', 'audience-rsa', 'subject-rsa', 'token-rsa');
    $decoded = $verifier->decode($token);

    expect($decoded->scope)->toBe('write');
    expect($decoded->iss)->toBe('issuer-rsa');
});

it('supports asymmetric key sets through kid resolution', function () {
    $altResource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    expect($altResource)->not->toBeFalse();
    openssl_pkey_export($altResource, $altPrivate);
    $altDetails = openssl_pkey_get_details($altResource);
    expect($altDetails)->toBeArray();
    $altPublic = $altDetails['key'];

    $issuer = new Asymmetric([
        'primary' => $this->privateKey,
        'backup' => $altPrivate,
    ]);
    $issuer->registerClaims('issuer-kid', 'audience-kid', 'subject-kid', 'token-kid');
    $now = time();
    $issuer->registerTime($now, $now + 600);
    $token = $issuer->encode(['scope' => 'read'], 'primary');

    $verifier = new Asymmetric([
        'primary' => $this->publicKey,
        'backup' => $altPublic,
    ]);
    $verifier->registerClaims('issuer-kid', 'audience-kid', 'subject-kid', 'token-kid');
    $decoded = $verifier->decode($token);

    expect($decoded->scope)->toBe('read');
});

it('rejects asymmetric JWT verification with the wrong public key', function () {
    $issuer = new Asymmetric($this->privateKey);
    $issuer->registerClaims('issuer-rsa', 'audience-rsa', 'subject-rsa', 'token-rsa');
    $now = time();
    $issuer->registerTime($now, $now + 600);
    $token = $issuer->encode(['scope' => 'write']);

    $wrongResource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    expect($wrongResource)->not->toBeFalse();
    $wrongDetails = openssl_pkey_get_details($wrongResource);
    expect($wrongDetails)->toBeArray();
    $wrongPublicKey = $wrongDetails['key'];

    $verifier = new Asymmetric($wrongPublicKey);
    $verifier->registerClaims('issuer-rsa', 'audience-rsa', 'subject-rsa', 'token-rsa');
    $verifier->decode($token);
})->throws(\Exception::class, 'Signature verification failed!');
