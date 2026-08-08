<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;

it('exports algorithm-bound eligible JWKS keys and verifies imported keys', function () {
    $pair = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    $ring = new KeyRing([
        new KeyRingEntry('rsa1', $pair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: 'issuer'),
        new KeyRingEntry('old', $pair['public'], KeyStatus::RETIRED, KeyPurpose::JWT_SIGNING, 'RS256', issuer: 'issuer'),
    ]);
    $jwks = new Jwks();
    $set = $jwks->exportFromKeyRing($ring, AsymmetricJwtAlgorithm::RS256, 'issuer');
    expect($set['keys'])->toHaveCount(1)->and($set['keys'][0]['alg'])->toBe('RS256');

    $publicKey = $jwks->resolvePublicKeyByKid($set, 'rsa1', AsymmetricJwtAlgorithm::RS256);
    $claims = JwtClaims::issue('issuer', 'subject', ['api'], 300);
    $token = AsymmetricJwt::issuer($pair['private'], 'at+jwt', 'rsa1', AsymmetricJwtAlgorithm::RS256)->issue($claims);
    expect(AsymmetricJwt::verifier($publicKey, JwtPolicy::accessToken('issuer', 'api'), AsymmetricJwtAlgorithm::RS256)->verify($token))
        ->toBeTrue();
});

it('rejects duplicate kid and incompatible JWK metadata', function () {
    $pair = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk($pair['public'], 'same', AsymmetricJwtAlgorithm::RS256);
    $jwks = new Jwks();

    expect(fn() => $jwks->resolveByKid(['keys' => [$jwk, $jwk]], 'same'))
        ->toThrow(KeyResolutionException::class);

    foreach ([
        ['use' => 'enc'],
        ['alg' => 'RS512'],
        ['kty' => 'EC'],
        ['key_ops' => ['sign']],
    ] as $changes) {
        expect(fn() => $jwks->importPublicKeyFromJwk(
            array_replace($jwk, $changes),
            AsymmetricJwtAlgorithm::RS256,
        ))->toThrow(KeyResolutionException::class);
    }

    $weakRsa = $jwk;
    $weakRsa['n'] = sodium_bin2base64("\x80" . str_repeat("\0", 127), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    expect(fn() => $jwks->importPublicKeyFromJwk($weakRsa, AsymmetricJwtAlgorithm::RS256))
        ->toThrow(KeyResolutionException::class);

    $ecPair = KeyPairGenerator::openSsl(
        OpenSslRsaBits::BITS_3072,
        OpenSslKeyType::EC,
        OpenSslCurveName::PRIME256V1,
    )->generate();
    $ec = $jwks->exportPublicKeyToJwk($ecPair['public'], 'ec', AsymmetricJwtAlgorithm::ES256);
    expect(fn() => $jwks->importPublicKeyFromJwk(
        array_replace($ec, ['crv' => 'P-384']),
        AsymmetricJwtAlgorithm::ES256,
    ))->toThrow(KeyResolutionException::class)
        ->and(fn() => $jwks->importPublicKeyFromJwk(
            array_replace($ec, ['x' => 'AA']),
            AsymmetricJwtAlgorithm::ES256,
        ))->toThrow(KeyResolutionException::class);
});
