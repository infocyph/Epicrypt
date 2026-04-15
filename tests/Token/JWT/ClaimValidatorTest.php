<?php

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Token\JWT\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;

it('validates registered jwt claims', function () {
    $validator = new JwtValidator(new RegisteredClaims('issuer', 'audience', 'subject', 'jti-123'));

    $claims = [
        'iss' => 'issuer',
        'aud' => 'audience',
        'sub' => 'subject',
        'jti' => 'jti-123',
        'nbf' => time() - 10,
        'exp' => time() + 300,
    ];

    $validator->validate($claims);

    expect(true)->toBeTrue();
});

it('rejects invalid registered jwt claims', function () {
    $validator = new JwtValidator(new RegisteredClaims('issuer', 'audience', 'subject', 'jti-123'));

    $claims = [
        'iss' => 'wrong',
        'aud' => 'audience',
        'sub' => 'subject',
        'jti' => 'jti-123',
        'nbf' => time() - 10,
        'exp' => time() + 300,
    ];

    expect(fn () => $validator->validate($claims))->toThrow(InvalidClaimException::class);
});
