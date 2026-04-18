<?php

use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Security\KeyRing;

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

it('verifies symmetric jwt tokens against a rotating key ring', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512))->encode($claims, 'active-secret');
    $jwt = new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );

    $ring = new KeyRing([
        'legacy' => 'legacy-secret',
        'active' => 'active-secret',
    ], 'active');

    expect($jwt->verifyWithAnyKey($token, $ring))->toBeTrue();
    expect($jwt->decodeWithAnyKey($token, $ring))->toBeObject();
    expect($jwt->verifyWithAnyKey($token, ['wrong-secret']))->toBeFalse();
});
