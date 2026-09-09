<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClientKeySet;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;

it('pins and resolves public client assertion keys by kid and algorithm', function () {
    $pair = KeyPairGenerator::ec()->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk(
        $pair['public'],
        'client-key-1',
        AsymmetricJwtAlgorithm::ES256,
    );
    $keys = new OAuthClientKeySet(['keys' => [$jwk]]);

    expect($keys->algorithms())->toBe([AsymmetricJwtAlgorithm::ES256])
        ->and($keys->resolvePublicKey('client-key-1', AsymmetricJwtAlgorithm::ES256))->toContain('BEGIN PUBLIC KEY')
        ->and($keys->resolvePublicKey(null, AsymmetricJwtAlgorithm::ES256))->toContain('BEGIN PUBLIC KEY');
});

it('rejects private key material in client assertion jwks', function () {
    $pair = KeyPairGenerator::ec()->generate();
    $jwk = new Jwks()->exportPublicKeyToJwk(
        $pair['public'],
        'client-key-1',
        AsymmetricJwtAlgorithm::ES256,
    );
    $jwk['d'] = 'private-material';

    expect(fn() => new OAuthClientKeySet(['keys' => [$jwk]]))->toThrow(ConfigurationException::class);
});

it('requires an unambiguous key when an assertion omits kid', function () {
    $one = KeyPairGenerator::ec()->generate();
    $two = KeyPairGenerator::ec()->generate();
    $jwks = new Jwks();
    $keys = new OAuthClientKeySet(['keys' => [
        $jwks->exportPublicKeyToJwk($one['public'], 'client-key-1', AsymmetricJwtAlgorithm::ES256),
        $jwks->exportPublicKeyToJwk($two['public'], 'client-key-2', AsymmetricJwtAlgorithm::ES256),
    ]]);

    expect(fn() => $keys->resolvePublicKey(null, AsymmetricJwtAlgorithm::ES256))->toThrow(KeyResolutionException::class);
});
