<?php

use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

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

it('encodes and decodes with Token/Jwt asymmetric services', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
        'scope' => 'api:write',
    ];

    $token = (new AsymmetricJwt(null, AsymmetricJwtAlgorithm::RS512))->encode($claims, $this->privateKey);
    $decoded = (new AsymmetricJwt(
        null,
        AsymmetricJwtAlgorithm::RS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    ))->decode($token, $this->publicKey);

    expect($decoded)->toBeObject();
    expect($decoded->scope)->toBe('api:write');
});

it('verifies tokens with Token/Jwt asymmetric verifier service', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $token = (new AsymmetricJwt(null, AsymmetricJwtAlgorithm::RS512))->encode($claims, $this->privateKey);
    $jwt = new AsymmetricJwt(
        null,
        AsymmetricJwtAlgorithm::RS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );

    expect($jwt->verify($token, $this->publicKey))->toBeTrue();

    $wrongKeyResource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    expect($wrongKeyResource)->not->toBeFalse();
    $wrongKeyDetails = openssl_pkey_get_details($wrongKeyResource);

    expect($wrongKeyDetails)->toBeArray();
    expect($jwt->verify($token, $wrongKeyDetails['key']))->toBeFalse();
});
