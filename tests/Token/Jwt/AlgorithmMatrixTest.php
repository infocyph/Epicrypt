<?php

use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\RequiredJwtClaims;

it('roundtrips symmetric jwt for HS256 HS384 and HS512', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
        $jwt = new SymmetricJwt($algorithm, new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'));
        $token = (new SymmetricJwt($algorithm))->encode($claims, 'super-secret-key');

        expect($jwt->verify($token, 'super-secret-key'))->toBeTrue();
    }
});

it('roundtrips asymmetric jwt for RS256 RS384 and RS512', function () {
    $resource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    if ($resource === false) {
        expect(true)->toBeTrue();

        return;
    }
    openssl_pkey_export($resource, $privateKey);
    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray();

    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    foreach ([AsymmetricJwtAlgorithm::RS256, AsymmetricJwtAlgorithm::RS384, AsymmetricJwtAlgorithm::RS512] as $algorithm) {
        $jwt = new AsymmetricJwt(null, $algorithm, new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'));
        $token = (new AsymmetricJwt(null, $algorithm))->encode($claims, $privateKey);

        expect($jwt->verify($token, $details['key']))->toBeTrue();
    }
});

it('roundtrips asymmetric jwt for ES256 ES384 and ES512 when supported', function () {
    $curveForAlgorithm = [
        AsymmetricJwtAlgorithm::ES256->value => 'prime256v1',
        AsymmetricJwtAlgorithm::ES384->value => 'secp384r1',
        AsymmetricJwtAlgorithm::ES512->value => 'secp521r1',
    ];

    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $asserted = false;

    foreach ([AsymmetricJwtAlgorithm::ES256, AsymmetricJwtAlgorithm::ES384, AsymmetricJwtAlgorithm::ES512] as $algorithm) {
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curveForAlgorithm[$algorithm->value],
        ]);

        if ($resource === false) {
            continue;
        }

        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        if (! is_array($details) || ! isset($details['key']) || ! is_string($details['key'])) {
            continue;
        }

        $jwt = new AsymmetricJwt(null, $algorithm, new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'));
        $token = (new AsymmetricJwt(null, $algorithm))->encode($claims, $privateKey);

        $asserted = true;
        expect($jwt->verify($token, $details['key']))->toBeTrue();
    }

    if (! $asserted) {
        expect(true)->toBeTrue();
    }
});

it('fails jwt key-set mode when kid is missing', function () {
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

    $result = $jwt->verifyResult($token, ['active' => 'active-secret']);

    expect($result->verified)->toBeFalse();
});

it('accepts a recently expired jwt when leeway is configured', function () {
    $issueClock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 1_000;
        }
    };
    $verifyClock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 1_003;
        }
    };

    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => 995,
        'exp' => 1_001,
    ];

    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512, clock: $issueClock))->encode($claims, 'super-secret-key');
    $expected = new ExpectedJwtClaims(
        issuer: 'issuer-service',
        audience: 'audience-service',
        subject: 'subject-service',
        jwtId: 'token-service',
        required: new RequiredJwtClaims(issuer: true, audience: true, subject: true, jwtId: true),
    );
    $options = new JwtValidationOptions(leewaySeconds: 5);
    $jwt = new SymmetricJwt(SymmetricJwtAlgorithm::HS512, $expected, $options, $verifyClock);

    expect($jwt->verifyResult($token, 'super-secret-key')->verified)->toBeTrue();
});
