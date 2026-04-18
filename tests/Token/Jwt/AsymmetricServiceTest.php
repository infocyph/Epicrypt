<?php

use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

beforeEach(function () {
    $resource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);

    if ($resource === false) {
        $this->markTestSkipped('OpenSSL key generation is unavailable in this environment.');
    }

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

it('verifies asymmetric jwt tokens against a rotating public key ring', function () {
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

    $wrongKeyResource = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    expect($wrongKeyResource)->not->toBeFalse();
    $wrongKeyDetails = openssl_pkey_get_details($wrongKeyResource);
    expect($wrongKeyDetails)->toBeArray();

    $ring = new KeyRing([
        'legacy' => $wrongKeyDetails['key'],
        'active' => $this->publicKey,
    ], 'active');
    $result = $jwt->verifyWithAnyKeyResult($token, $ring);

    expect($jwt->verifyWithAnyKey($token, $ring))->toBeTrue();
    expect($jwt->decodeWithAnyKey($token, $ring))->toBeObject();
    expect($result->verified)->toBeTrue();
    expect($result->matchedKeyId)->toBe('active');
    expect($result->usedFallbackKey)->toBeFalse();
    expect($jwt->verifyWithAnyKey($token, [$wrongKeyDetails['key']]))->toBeFalse();
});

it('blocks asymmetric jwt issuing in legacy-decrypt-only mode', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $jwt = AsymmetricJwt::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);

    expect(fn () => $jwt->encode($claims, $this->privateKey))
        ->toThrow('JWT issuing is disabled for the legacy-decrypt-only profile.');
});

it('still verifies asymmetric jwt tokens in legacy-decrypt-only mode', function () {
    $now = time();
    $claims = [
        'iss' => 'issuer-service',
        'aud' => 'audience-service',
        'sub' => 'subject-service',
        'jti' => 'token-service',
        'nbf' => $now,
        'exp' => $now + 600,
    ];

    $token = AsymmetricJwt::forProfile(SecurityProfile::MODERN)->encode($claims, $this->privateKey);
    $jwt = AsymmetricJwt::forProfile(
        SecurityProfile::LEGACY_DECRYPT_ONLY,
        new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-service'),
    );

    expect($jwt->verify($token, $this->publicKey))->toBeTrue();
    expect($jwt->decode($token, $this->publicKey))->toBeObject();
});
