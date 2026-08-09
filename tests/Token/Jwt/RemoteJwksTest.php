<?php

declare(strict_types=1);

use Http\Mock\Client;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;

it('uses one forced refresh to resolve a rolled over remote key', function () {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $old = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    $current = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    $jwks = new Jwks();
    $oldSet = ['keys' => [$jwks->exportPublicKeyToJwk($old['public'], 'old', AsymmetricJwtAlgorithm::RS256)]];
    $currentSet = ['keys' => [$jwks->exportPublicKeyToJwk($current['public'], 'current', AsymmetricJwtAlgorithm::RS256)]];
    $client->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode($oldSet, JSON_THROW_ON_ERROR)));
    $client->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode($currentSet, JSON_THROW_ON_ERROR)));

    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration('https://issuer.example', 'https://keys.example/jwks'),
    );

    expect($remote->resolve('current', AsymmetricJwtAlgorithm::RS256))->toContain('PUBLIC KEY')
        ->and($client->getRequests())->toHaveCount(2);
});

it('binds discovery to the configured issuer and enforces response bounds', function () {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $client->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
        'issuer' => 'https://attacker.example',
        'jwks_uri' => 'https://keys.example/jwks',
    ], JSON_THROW_ON_ERROR)));
    $remote = new RemoteJwks($client, $factory, new RemoteJwksConfiguration('https://issuer.example'));
    expect(fn() => $remote->load())->toThrow(KeyResolutionException::class);

    $oversized = new Client($factory);
    $oversized->addResponse(new Response(200, ['Content-Type' => 'application/json'], str_repeat('x', 1025)));
    $bounded = new RemoteJwks(
        $oversized,
        $factory,
        new RemoteJwksConfiguration(
            'https://issuer.example',
            'https://keys.example/jwks',
            maximumResponseBytes: 1024,
        ),
    );
    expect(fn() => $bounded->load())->toThrow(KeyResolutionException::class);
});
