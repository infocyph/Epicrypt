<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\SignedUrl;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\RequiredJwtClaims;
use Infocyph\Epicrypt\Token\Payload\SignedPayload;

it('exposes jwt decode result metadata', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];
    $jwt = new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );
    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512))->encode($claims, 'super-secret-key');
    $result = $jwt->decodeResult($token, 'super-secret-key');

    expect($result->verified)->toBeTrue();
    expect($result->algorithm)->toBe('HS512');
    expect($result->headers['typ'] ?? null)->toBe('JWT');
});

it('rejects missing typ, crit header, none alg and non-string kid in strict mode', function () {
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
    [$h, $p] = explode('.', $token, 3);
    $payload = Json::decodeToArray(Base64Url::decode($p));

    $strictJwt = new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
        new JwtValidationOptions(strictTyp: true),
    );

    $cases = [
        ['alg' => 'HS512'], // missing typ
        ['alg' => 'HS512', 'typ' => 'JWT', 'crit' => ['exp']],
        ['alg' => 'none', 'typ' => 'JWT'],
        ['alg' => 'HS512', 'typ' => 'JWT', 'kid' => 10],
    ];

    foreach ($cases as $header) {
        $eh = Base64Url::encode(Json::encode($header));
        $ep = Base64Url::encode(Json::encode($payload));
        $sig = Base64Url::encode(hash_hmac('sha512', $eh.'.'.$ep, 'super-secret-key', true));
        $tampered = $eh.'.'.$ep.'.'.$sig;

        expect($strictJwt->verifyResult($tampered, 'super-secret-key')->verified)->toBeFalse();
    }
});

it('keeps configured alg when custom headers try to override alg', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];
    $jwt = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
    $token = $jwt->encode($claims, 'super-secret-key', ['alg' => 'HS256']);
    [$h] = explode('.', $token, 2);
    $header = Json::decodeToArray(Base64Url::decode($h));

    expect($header['alg'] ?? null)->toBe('HS512');
});

it('exposes signed payload verification result metadata', function () {
    $payload = new SignedPayload('reset_password');
    $token = $payload->encode(
        ['sub' => 'user-1', 'purpose' => 'reset'],
        'active-secret',
        ['exp' => time() + 600],
    );
    $result = $payload->verifyResult($token, 'active-secret');

    expect($result->verified)->toBeTrue();
    expect($result->claims['sub'] ?? null)->toBe('user-1');
});

it('exposes signed url verification result metadata', function () {
    $signedUrl = new SignedUrl('url-secret');
    $signed = $signedUrl->generate('https://example.com/download', ['file' => 'report'], time() + 300);
    $result = $signedUrl->verifyResult($signed);

    expect($result->verified)->toBeTrue();
    expect($result->invalidSignature)->toBeFalse();
    expect($result->version)->toBe(1);
});

it('supports expected/required jwt claims with max token age', function () {
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
            return 1_500;
        }
    };

    $claims = [
        'iss' => 'issuer-service',
        'nbf' => 1_000,
        'exp' => 2_000,
    ];
    $token = (new SymmetricJwt(SymmetricJwtAlgorithm::HS512, clock: $issueClock))->encode($claims, 'super-secret-key');

    $expected = new ExpectedJwtClaims(
        issuer: 'issuer-service',
        required: new RequiredJwtClaims(issuer: true),
        maxTokenAgeSeconds: 200,
    );
    $result = (new SymmetricJwt(
        SymmetricJwtAlgorithm::HS512,
        $expected,
        clock: $verifyClock,
    ))->verifyResult($token, 'super-secret-key');

    expect($result->verified)->toBeFalse();
    expect($result->expired)->toBeTrue();
});
