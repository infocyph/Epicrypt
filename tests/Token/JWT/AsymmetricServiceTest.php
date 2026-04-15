<?php

use Infocyph\Epicrypt\Token\JWT\Asymmetric\JwtDecoder;
use Infocyph\Epicrypt\Token\JWT\Asymmetric\JwtEncoder;
use Infocyph\Epicrypt\Token\JWT\Asymmetric\JwtVerifier;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;

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

it('encodes and decodes with Token/JWT asymmetric services', function () {
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

    $encoder = new JwtEncoder(null, 'RS512');
    $token = $encoder->encode($claims, $this->privateKey);

    $decoder = new JwtDecoder(
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
        null,
        'RS512',
    );
    $decoded = $decoder->decode($token, $this->publicKey);

    expect($decoded)->toBeObject();
    expect($decoded->scope)->toBe('api:write');
});

it('verifies tokens with Token/JWT asymmetric verifier service', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $encoder = new JwtEncoder(null, 'RS512');
    $token = $encoder->encode($claims, $this->privateKey);

    $verifier = new JwtVerifier(
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
        null,
        'RS512',
    );

    expect($verifier->verify($token, $this->publicKey))->toBeTrue();

    $wrongKeyResource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    expect($wrongKeyResource)->not->toBeFalse();
    $wrongKeyDetails = openssl_pkey_get_details($wrongKeyResource);

    expect($wrongKeyDetails)->toBeArray();
    expect($verifier->verify($token, $wrongKeyDetails['key']))->toBeFalse();
});
