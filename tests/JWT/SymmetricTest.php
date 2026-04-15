<?php

use Infocyph\Epicrypt\JWT\Symmetric;

it('encodes and decodes a symmetric JWT with a single secret', function () {
    $jwt = new Symmetric('super-secret-key');
    $jwt->registerClaims('issuer-a', 'audience-a', 'subject-a', 'token-1');
    $now = time();
    $jwt->registerTime($now, $now + 600);

    $token = $jwt->encode(['role' => 'admin']);
    $decoded = $jwt->decode($token);

    expect($decoded->role)->toBe('admin');
    expect($decoded->iss)->toBe('issuer-a');
    expect($decoded->aud)->toBe('audience-a');
});

it('supports symmetric key sets through kid resolution', function () {
    $secrets = [
        'primary' => 'primary-secret-key',
        'backup' => 'backup-secret-key',
    ];

    $issuer = new Symmetric($secrets);
    $issuer->registerClaims('issuer-kid', 'audience-kid', 'subject-kid', 'token-kid');
    $now = time();
    $issuer->registerTime($now, $now + 600);
    $token = $issuer->encode(['scope' => 'read'], 'primary');

    $verifier = new Symmetric($secrets);
    $verifier->registerClaims('issuer-kid', 'audience-kid', 'subject-kid', 'token-kid');
    $decoded = $verifier->decode($token);

    expect($decoded->scope)->toBe('read');
});

it('requires kid when symmetric key-set mode is used', function () {
    $jwt = new Symmetric(['primary' => 'primary-secret-key']);
    $jwt->registerClaims('issuer-a', 'audience-a', 'subject-a', 'token-1');
    $now = time();
    $jwt->registerTime($now, $now + 600);

    $jwt->encode(['role' => 'admin']);
})->throws(\Exception::class, '"kid" invalid, lookup failed!');

it('rejects symmetric JWT decode when registered issuer mismatches', function () {
    $issuer = new Symmetric('super-secret-key');
    $issuer->registerClaims('issuer-a', 'audience-a', 'subject-a', 'token-1');
    $now = time();
    $issuer->registerTime($now, $now + 600);
    $token = $issuer->encode(['role' => 'admin']);

    $verifier = new Symmetric('super-secret-key');
    $verifier->registerClaims('issuer-b', 'audience-a', 'subject-a', 'token-1');
    $verifier->decode($token);
})->throws(\Exception::class, 'Token verification failed!');
