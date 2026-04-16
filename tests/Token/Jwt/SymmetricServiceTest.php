<?php

use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

it('encodes and decodes with Token/Jwt symmetric services', function () {
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

    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512))->encode($claims, 'super-secret-key');
    $decoded = (new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    ))->decode($token, 'super-secret-key');

    expect($decoded)->toBeObject();
    expect($decoded->scope)->toBe('admin');
});

it('verifies tokens with Token/Jwt symmetric verifier service', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512))->encode($claims, 'super-secret-key');
    $jwt = new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );

    expect($jwt->verify($token, 'super-secret-key'))->toBeTrue();
    expect($jwt->verify($token, 'wrong-secret'))->toBeFalse();
});
