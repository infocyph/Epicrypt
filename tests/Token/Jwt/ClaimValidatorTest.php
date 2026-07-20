<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

it('validates registered jwt claims', function () {
    $validator = new JwtValidator(ExpectedJwtClaims::fromRegistered(new RegisteredClaims('issuer', 'audience', 'subject', 'jti-123')));

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
    $validator = new JwtValidator(ExpectedJwtClaims::fromRegistered(new RegisteredClaims('issuer', 'audience', 'subject', 'jti-123')));

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
