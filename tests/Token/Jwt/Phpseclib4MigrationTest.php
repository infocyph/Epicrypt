<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use phpseclib4\Crypt\PublicKeyLoader;

it('uses only the native phpseclib 4 namespace', function () {
    expect(class_exists(PublicKeyLoader::class))->toBeTrue()
        ->and(class_exists('phpseclib3\\Crypt\\PublicKeyLoader'))->toBeFalse();
});

it('signs PS256 with a password-protected private key', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $resource = openssl_pkey_get_private($pair['private']);
    expect($resource)->not->toBeFalse();

    $passphrase = 'phase-c-passphrase';
    $encryptedPrivate = '';
    expect(openssl_pkey_export($resource, $encryptedPrivate, $passphrase))->toBeTrue();

    $signer = Jws::signer($encryptedPrivate, AsymmetricJwtAlgorithm::PS256, 'ps256-v4', $passphrase);
    $verifier = Jws::verifier($pair['public'], AsymmetricJwtAlgorithm::PS256, 'ps256-v4');
    $token = $signer->signCompact('phpseclib-4');

    expect($verifier->verifyCompact($token))->toBeTrue()
        ->and(fn () => Jws::signer($encryptedPrivate, AsymmetricJwtAlgorithm::PS256, 'ps256-v4', 'wrong'))
        ->toThrow(ConfigurationException::class);
});

it('round trips password-protected RSA private JWK material', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $resource = openssl_pkey_get_private($pair['private']);
    expect($resource)->not->toBeFalse();

    $passphrase = 'jwk-v4-passphrase';
    $encryptedPrivate = '';
    expect(openssl_pkey_export($resource, $encryptedPrivate, $passphrase))->toBeTrue();

    $jwks = new Jwks();
    $jwk = $jwks->exportPrivateKeyToJwk(
        $encryptedPrivate,
        'rsa-v4',
        AsymmetricJwtAlgorithm::PS256,
        $passphrase,
    );
    $imported = $jwks->importPrivateKeyFromJwk($jwk, AsymmetricJwtAlgorithm::PS256);

    $signer = Jws::signer($imported, AsymmetricJwtAlgorithm::PS256, 'rsa-v4');
    $verifier = Jws::verifier($pair['public'], AsymmetricJwtAlgorithm::PS256, 'rsa-v4');

    expect($jwk)->toHaveKeys(['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'])
        ->and($verifier->verifyCompact($signer->signCompact('private-jwk-v4')))->toBeTrue()
        ->and(fn () => $jwks->exportPrivateKeyToJwk(
            $encryptedPrivate,
            'rsa-v4',
            AsymmetricJwtAlgorithm::PS256,
            'wrong',
        ))->toThrow(KeyResolutionException::class);
});

it('maps phpseclib 4 RSA OAEP failures to Epicrypt token errors', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $issuer = new Jwe($pair['public'], JweKeyManagementAlgorithm::RSA_OAEP_256);
    $recipient = new Jwe($pair['private'], JweKeyManagementAlgorithm::RSA_OAEP_256);
    $token = $issuer->encryptCompact('oaep-v4');

    expect($recipient->decryptCompact($token))->toBe('oaep-v4');

    $parts = explode('.', $token);
    $parts[1] = substr($parts[1], 0, -1) . ($parts[1][-1] === 'A' ? 'B' : 'A');

    expect(fn () => $recipient->decryptCompact(implode('.', $parts)))
        ->toThrow(InvalidTokenException::class);
});
