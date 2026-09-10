<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientSecret;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('models an exact public authorization-code client', function () {
    $client = new OAuthClient(
        clientId: 'browser-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::REFRESH_TOKEN],
        scopes: ['openid', 'orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );

    expect($client->allowsRedirectUri('https://client.example/callback'))->toBeTrue()
        ->and($client->allowsRedirectUri('https://client.example/callback/'))->toBeFalse()
        ->and($client->allowsGrant(OAuthGrantType::REFRESH_TOKEN))->toBeTrue()
        ->and($client->allowsScope('orders:read'))->toBeTrue()
        ->and($client->allowsAudience('orders-api'))->toBeTrue();
});

it('models a confidential client with one-way secret authentication', function () {
    $secret = OAuthClientSecret::hash('a-secret-value-long-enough-for-a-real-client');
    $client = new OAuthClient(
        clientId: 'service-client',
        type: OAuthClientType::CONFIDENTIAL,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: ['orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::CLIENT_SECRET_BASIC],
        secret: $secret,
    );

    expect($client->verifySecret('a-secret-value-long-enough-for-a-real-client'))->toBeTrue()
        ->and($client->verifySecret('wrong'))->toBeFalse()
        ->and($secret->encodedHash())->not->toContain('a-secret-value-long-enough-for-a-real-client');
});

it('requires at least one registered resource audience', function () {
    $create = static fn() => new OAuthClient(
        clientId: 'audienceless-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: [],
        audiences: [],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );

    expect($create)->toThrow(ConfigurationException::class);
});

it('rejects public clients that carry confidential credentials', function () {
    $create = static fn() => new OAuthClient(
        clientId: 'bad-public-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: [],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
        secret: OAuthClientSecret::hash('a-secret-value-long-enough-for-a-real-client'),
    );

    expect($create)->toThrow(ConfigurationException::class);
});

it('rejects unsupported grant and redirect profiles', function () {
    $publicCredentials = static fn() => new OAuthClient(
        clientId: 'public-service',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::CLIENT_CREDENTIALS],
        scopes: [],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
    $refreshOnly = static fn() => new OAuthClient(
        clientId: 'refresh-only',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: [],
        grantTypes: [OAuthGrantType::REFRESH_TOKEN],
        scopes: [],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
    $fragmentRedirect = static fn() => new OAuthClient(
        clientId: 'fragment-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback#fragment'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: [],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );

    expect($publicCredentials)->toThrow(ConfigurationException::class)
        ->and($refreshOnly)->toThrow(ConfigurationException::class)
        ->and($fragmentRedirect)->toThrow(ConfigurationException::class);
});
