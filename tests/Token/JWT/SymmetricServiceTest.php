<?php

use Infocyph\Epicrypt\Token\JWT\Symmetric\JwtDecoder;
use Infocyph\Epicrypt\Token\JWT\Symmetric\JwtEncoder;
use Infocyph\Epicrypt\Token\JWT\Symmetric\JwtVerifier;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;

it('encodes and decodes with Token/JWT symmetric services', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
        'scope' => 'admin',
    ];

    $encoder = new JwtEncoder('HS512');
    $token = $encoder->encode($claims, 'super-secret-key');

    $decoder = new JwtDecoder(
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
        'HS512',
    );
    $decoded = $decoder->decode($token, 'super-secret-key');

    expect($decoded)->toBeObject();
    expect($decoded->scope)->toBe('admin');
});

it('verifies tokens with Token/JWT symmetric verifier service', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $encoder = new JwtEncoder('HS512');
    $token = $encoder->encode($claims, 'super-secret-key');

    $verifier = new JwtVerifier(
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
        'HS512',
    );

    expect($verifier->verify($token, 'super-secret-key'))->toBeTrue();
    expect($verifier->verify($token, 'wrong-secret'))->toBeFalse();
});
