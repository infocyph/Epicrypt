<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
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
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
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

it('canonicalizes shortened OpenSSL EC coordinates to the JOSE curve width', function () {
    $publicKey = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAIdDyzcInokZyDBqjBpBctKCo2bp
L4Bl760o/+mUptRaQ6DaSVxuGeo5OXMda8UYziueQnxCXDFnK0K5ZFcrbA==
-----END PUBLIC KEY-----
PEM;
    $resource = openssl_pkey_get_public($publicKey);
    expect($resource)->not->toBeFalse();
    $details = openssl_pkey_get_details($resource);
    expect($details)->toBeArray()
        ->and(strlen($details['ec']['x']))->toBe(31)
        ->and(strlen($details['ec']['y']))->toBe(32);

    $jwks = new Jwks();
    $jwk = $jwks->exportPublicKeyToJwk($publicKey, 'short-x', AsymmetricJwtAlgorithm::ES256);
    $x = sodium_base642bin((string) $jwk['x'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $y = sodium_base642bin((string) $jwk['y'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

    expect($x)->toHaveLength(32)
        ->and($x[0])->toBe("\x00")
        ->and($y)->toHaveLength(32)
        ->and($jwks->importPublicKeyFromJwk($jwk, AsymmetricJwtAlgorithm::ES256))->toContain('BEGIN PUBLIC KEY');
});

it('supports OKP, oct, thumbprints and mixed algorithm sets', function () {
    $jwks = new Jwks();
    $ed = KeyPairGenerator::sodiumSign()->generate();
    $okp = $jwks->exportOkpPublicKey($ed['public'], 'ed-1');
    $secret = random_bytes(64);
    $oct = $jwks->exportSymmetricSecretJwk($secret, 'shared-1', 'HS512');

    expect($jwks->importOkpPublicKey($okp, 'EdDSA', 'Ed25519'))->toBe($ed['public'])
        ->and($jwks->importSymmetricKey($oct, 'HS512'))->toBe($secret)
        ->and($jwks->thumbprint($okp))->toHaveLength(43)
        ->and($jwks->thumbprintUri($okp))->toStartWith('urn:ietf:params:oauth:jwk-thumbprint:sha-256:');

    $rsa = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $ring = new KeyRing([
        new KeyRingEntry('rs', $rsa['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: 'issuer'),
        new KeyRingEntry('ps', $rsa['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'PS256', issuer: 'issuer'),
    ]);
    expect($jwks->exportMixedFromKeyRing(
        $ring,
        [AsymmetricJwtAlgorithm::RS256, AsymmetricJwtAlgorithm::PS256],
        'issuer',
    )['keys'])->toHaveCount(2);
});

it('rejects duplicate kid and incompatible JWK metadata', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk($pair['public'], 'same', AsymmetricJwtAlgorithm::RS256);
    $jwks = new Jwks();

    expect(fn() => $jwks->resolveByKid(['keys' => [$jwk, $jwk]], 'same'))
        ->toThrow(KeyResolutionException::class);

    foreach ([
        ['use' => 'enc'],
        ['alg' => 'RS512'],
        ['kty' => 'EC'],
        ['key_ops' => ['sign']],
        ['key_ops' => ['verify', 'sign']],
        ['key_ops' => ['verify', 'verify']],
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

    expect(fn() => $jwks->importPublicKeyFromJwk(
        array_replace($jwk, ['e' => 'Ag']),
        AsymmetricJwtAlgorithm::RS256,
    ))->toThrow(KeyResolutionException::class);

    $ecPair = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
    $ec = $jwks->exportPublicKeyToJwk($ecPair['public'], 'ec', AsymmetricJwtAlgorithm::ES256);
    expect(fn() => $jwks->importPublicKeyFromJwk(
        array_replace($ec, ['crv' => 'P-384']),
        AsymmetricJwtAlgorithm::ES256,
    ))->toThrow(KeyResolutionException::class)
        ->and(fn() => $jwks->importPublicKeyFromJwk(
            array_replace($ec, ['x' => 'AA']),
            AsymmetricJwtAlgorithm::ES256,
        ))->toThrow(KeyResolutionException::class)
        ->and(fn() => $jwks->importPublicKeyFromJwk(
            array_replace($ec, [
                'x' => sodium_bin2base64(str_repeat("\x01", 32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
                'y' => sodium_bin2base64(str_repeat("\x01", 32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            ]),
            AsymmetricJwtAlgorithm::ES256,
        ))->toThrow(KeyResolutionException::class);
});

it('round trips explicitly requested private JWK material', function () {
    $jwks = new Jwks();
    $rsa = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $private = $jwks->exportPrivateKeyToJwk($rsa['private'], 'private-rsa', AsymmetricJwtAlgorithm::PS256);
    expect($private)->toHaveKeys(['d', 'p', 'q', 'dp', 'dq', 'qi'])
        ->and($jwks->importPrivateKeyFromJwk($private, AsymmetricJwtAlgorithm::PS256))->toContain('PRIVATE KEY');

    $ed = KeyPairGenerator::sodiumSign()->generate();
    $okp = $jwks->exportOkpPrivateKey($ed['private'], 'private-ed');
    expect($okp)->toHaveKey('d')
        ->and($jwks->importOkpPrivateKey($okp, 'EdDSA', 'Ed25519'))->toBe($ed['private']);

    $incomplete = $private;
    unset($incomplete['qi']);
    expect(fn() => $jwks->importPrivateKeyFromJwk($incomplete, AsymmetricJwtAlgorithm::PS256))
        ->toThrow(KeyResolutionException::class);
});

it('uses interoperable X25519 JWK operations', function () {
    $jwks = new Jwks();
    $pair = KeyPairGenerator::sodium()->generate();
    $public = $jwks->exportOkpPublicKey($pair['public'], 'x25519-public', 'ECDH-ES', 'X25519');
    $private = $jwks->exportOkpPrivateKey($pair['private'], 'x25519-private', 'ECDH-ES', 'X25519');

    expect($public)->not->toHaveKey('key_ops')
        ->and($private['key_ops'])->toBe(['deriveBits'])
        ->and($jwks->importOkpPublicKey($public, 'ECDH-ES', 'X25519'))->toBe($pair['public'])
        ->and($jwks->importOkpPrivateKey($private, 'ECDH-ES', 'X25519'))->toBe($pair['private']);
});

it('binds a JWK to the matching leaf certificate', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $certificate = new CertificateBuilder()->selfSign(['commonName' => 'jwk.example'], $pair['private']);
    $jwks = new Jwks();
    $jwk = $jwks->exportPublicKeyToJwk($pair['public'], 'cert-key', AsymmetricJwtAlgorithm::RS256);
    $bound = $jwks->bindCertificateChain($jwk, [$certificate]);

    expect($bound)->toHaveKeys(['x5c', 'x5t', 'x5t#S256']);
    $jwks->validateCertificateBinding($bound);

    $other = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $mismatched = $jwks->exportPublicKeyToJwk($other['public'], 'other', AsymmetricJwtAlgorithm::RS256);
    expect(fn() => $jwks->bindCertificateChain($mismatched, [$certificate]))
        ->toThrow(KeyResolutionException::class)
        ->and(fn () => $jwks->validateCertificateBinding(array_replace($bound, ['x5t' => str_repeat('A', 27)])))
        ->toThrow(KeyResolutionException::class)
        ->and(fn () => $jwks->validateCertificateBinding(array_replace($bound, ['x5t#S256' => str_repeat('A', 43)])))
        ->toThrow(KeyResolutionException::class)
        ->and(fn () => $jwks->bindCertificateChain($jwk, [$certificate, 'not-a-certificate']))
        ->toThrow(KeyResolutionException::class);
});
