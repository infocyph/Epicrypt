<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\OpenSSL\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\SigningKeyReadinessException;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Security\SigningKeyReadinessFailureReason;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

$rsaPair = static fn(?string $passphrase = null): array => (new KeyPairGenerator(OpenSslRsaBits::BITS_2048))->generate($passphrase);

it('validates an RSA signing set and exports public-only active and fallback JWKS', function () use ($rsaPair) {
    $issuer = 'https://issuer.example';
    $active = $rsaPair();
    $fallback = $rsaPair();
    $ring = new KeyRing([
        new KeyRingEntry('rsa-old', $fallback['public'], KeyStatus::FALLBACK, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
        new KeyRingEntry('rsa-active', $active['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
    ]);

    $set = new AsymmetricSigningKeySet(
        issuer: $issuer,
        activeKeyId: 'rsa-active',
        privateKey: $active['private'],
        publicKeys: $ring,
        algorithm: AsymmetricJwtAlgorithm::RS256,
    );

    $jwks = $set->jwks();
    expect($set->activeMetadata()->id)->toBe('rsa-active')
        ->and($set->activeMetadata()->status)->toBe(KeyStatus::ACTIVE)
        ->and($set->privateKey())->toBe($active['private'])
        ->and($set->publicKeys())->toBe($ring)
        ->and(array_column($jwks['keys'], 'kid'))->toBe(['rsa-active', 'rsa-old'])
        ->and($jwks['keys'])->toHaveCount(2);

    foreach ($jwks['keys'] as $jwk) {
        expect($jwk['kty'] ?? null)->toBe('RSA')
            ->and($jwk)->not->toHaveKey('d')
            ->and($jwk)->not->toHaveKey('p')
            ->and($jwk)->not->toHaveKey('q');
    }
});

it('loads encrypted RSA-PSS private keys for readiness without exposing loader errors', function () use ($rsaPair) {
    $issuer = 'https://issuer.example';
    $pair = $rsaPair('correct horse battery staple');
    $ring = new KeyRing([
        new KeyRingEntry('ps-active', $pair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'PS256', issuer: $issuer),
    ]);

    $ready = new AsymmetricSigningKeySet(
        $issuer,
        'ps-active',
        $pair['private'],
        $ring,
        AsymmetricJwtAlgorithm::PS256,
        'correct horse battery staple',
    );

    expect($ready->activeMetadata()->id)->toBe('ps-active')
        ->and($ready->privateKeyPassphrase())->toBe('correct horse battery staple');

    try {
        new AsymmetricSigningKeySet(
            $issuer,
            'ps-active',
            $pair['private'],
            $ring,
            AsymmetricJwtAlgorithm::PS256,
            'wrong passphrase',
        );
        test()->fail('Expected encrypted private-key readiness to fail.');
    } catch (SigningKeyReadinessException $exception) {
        expect($exception->reason)->toBe(SigningKeyReadinessFailureReason::PRIVATE_KEY_INVALID)
            ->and($exception->getPrevious())->toBeNull()
            ->and($exception->getMessage())->toBe(SigningKeyReadinessFailureReason::PRIVATE_KEY_INVALID->message());
    }
});

it('validates EC signing pairs through canonical public JWK identity', function () {
    $issuer = 'https://issuer.example';
    $pair = (new KeyPairGenerator(null, OpenSslCurveName::PRIME256V1))->generate();
    $ring = new KeyRing([
        new KeyRingEntry('ec-active', $pair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'ES256', issuer: $issuer),
    ]);

    $set = new AsymmetricSigningKeySet(
        $issuer,
        'ec-active',
        $pair['private'],
        $ring,
        AsymmetricJwtAlgorithm::ES256,
    );

    expect($set->jwks()['keys'][0]['kty'] ?? null)->toBe('EC')
        ->and($set->jwks()['keys'][0]['crv'] ?? null)->toBe('P-256');
});

it('validates Ed25519 signing pairs and exports OKP JWKS without private material', function () {
    $issuer = 'https://issuer.example';
    $keyPair = sodium_crypto_sign_keypair();
    $privateKey = sodium_crypto_sign_secretkey($keyPair);
    $publicKey = sodium_crypto_sign_publickey($keyPair);
    $ring = new KeyRing([
        new KeyRingEntry('ed-active', $publicKey, KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'EdDSA', issuer: $issuer),
    ]);

    $set = new AsymmetricSigningKeySet(
        $issuer,
        'ed-active',
        $privateKey,
        $ring,
        AsymmetricJwtAlgorithm::EDDSA,
    );
    $jwk = $set->jwks()['keys'][0];

    expect($jwk['kty'] ?? null)->toBe('OKP')
        ->and($jwk['crv'] ?? null)->toBe('Ed25519')
        ->and($jwk['kid'] ?? null)->toBe('ed-active')
        ->and($jwk)->not->toHaveKey('d');
});

it('reports a typed key-pair mismatch without cryptographic backend details', function () use ($rsaPair) {
    $issuer = 'https://issuer.example';
    $publicPair = $rsaPair();
    $privatePair = $rsaPair();
    $ring = new KeyRing([
        new KeyRingEntry('rsa-active', $publicPair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
    ]);

    try {
        new AsymmetricSigningKeySet(
            $issuer,
            'rsa-active',
            $privatePair['private'],
            $ring,
            AsymmetricJwtAlgorithm::RS256,
        );
        test()->fail('Expected mismatched signing keys to fail readiness.');
    } catch (SigningKeyReadinessException $exception) {
        expect($exception->reason)->toBe(SigningKeyReadinessFailureReason::KEY_PAIR_MISMATCH)
            ->and($exception->getPrevious())->toBeNull()
            ->and($exception->getMessage())->toBe(SigningKeyReadinessFailureReason::KEY_PAIR_MISMATCH->message());
    }
});

it('rejects active-id inconsistencies and invalid fallback public keys with typed reasons', function () use ($rsaPair) {
    $issuer = 'https://issuer.example';
    $pair = $rsaPair();
    $validRing = new KeyRing([
        new KeyRingEntry('rsa-active', $pair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
    ]);

    try {
        new AsymmetricSigningKeySet(
            $issuer,
            'other-id',
            $pair['private'],
            $validRing,
            AsymmetricJwtAlgorithm::RS256,
        );
        test()->fail('Expected active key id mismatch to fail readiness.');
    } catch (SigningKeyReadinessException $exception) {
        expect($exception->reason)->toBe(SigningKeyReadinessFailureReason::ACTIVE_KEY_ID_MISMATCH);
    }

    $invalidFallbackRing = new KeyRing([
        new KeyRingEntry('rsa-active', $pair['public'], KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
        new KeyRingEntry('rsa-old', 'not-a-public-key', KeyStatus::FALLBACK, KeyPurpose::JWT_SIGNING, 'RS256', issuer: $issuer),
    ]);

    try {
        new AsymmetricSigningKeySet(
            $issuer,
            'rsa-active',
            $pair['private'],
            $invalidFallbackRing,
            AsymmetricJwtAlgorithm::RS256,
        );
        test()->fail('Expected invalid fallback public key to fail readiness.');
    } catch (SigningKeyReadinessException $exception) {
        expect($exception->reason)->toBe(SigningKeyReadinessFailureReason::PUBLIC_KEY_SET_INVALID);
    }
});
