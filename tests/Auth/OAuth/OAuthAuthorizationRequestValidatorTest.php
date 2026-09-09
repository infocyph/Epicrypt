<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;

function authorizationClient(): OAuthClient
{
    return new OAuthClient(
        clientId: 'client-1',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: ['read', 'openid'],
        audiences: [],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
}

function authorizationValidator(): OAuthAuthorizationRequestValidator
{
    return new OAuthAuthorizationRequestValidator(new InMemoryOAuthClientStore([authorizationClient()]));
}

/** @return array<string, string|list<string>> */
function validAuthorizationParameters(): array
{
    return [
        'client_id' => 'client-1',
        'redirect_uri' => 'https://client.example/callback',
        'response_type' => 'code',
        'scope' => 'read',
        'state' => 'state-1',
        'code_challenge' => str_repeat('A', 43),
        'code_challenge_method' => 'S256',
    ];
}

it('accepts an exact authorization-code request with S256 PKCE', function () {
    $result = authorizationValidator()->validate(validAuthorizationParameters());

    expect($result->error)->toBeNull()
        ->and($result->acceptedRequest()->clientId)->toBe('client-1')
        ->and($result->acceptedRequest()->redirectUri)->toBe('https://client.example/callback')
        ->and($result->acceptedRequest()->scopes)->toBe(['read'])
        ->and($result->acceptedRequest()->state)->toBe('state-1');
});

it('never redirects a redirect-uri mismatch', function () {
    $parameters = validAuthorizationParameters();
    $parameters['redirect_uri'] = 'https://attacker.example/callback';
    $result = authorizationValidator()->validate($parameters);

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->mayRedirect())->toBeFalse();
});

it('rejects duplicate singleton parameters before client resolution', function () {
    $parameters = validAuthorizationParameters();
    $parameters['client_id'] = ['client-1', 'client-1'];
    $result = authorizationValidator()->validate($parameters);

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->redirectUri)->toBeNull();
});

it('rejects missing PKCE after establishing a safe redirect', function () {
    $parameters = validAuthorizationParameters();
    unset($parameters['code_challenge']);
    $result = authorizationValidator()->validate($parameters);

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->redirectUri)->toBe('https://client.example/callback')
        ->and($result->error?->state)->toBe('state-1');
});

it('rejects plain PKCE', function () {
    $parameters = validAuthorizationParameters();
    $parameters['code_challenge_method'] = 'plain';

    expect(authorizationValidator()->validate($parameters)->error?->code)
        ->toBe(OAuthErrorCode::INVALID_REQUEST);
});

it('rejects scopes outside the client registration', function () {
    $parameters = validAuthorizationParameters();
    $parameters['scope'] = 'read admin';
    $result = authorizationValidator()->validate($parameters);

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_SCOPE)
        ->and($result->error?->redirectUri)->toBe('https://client.example/callback');
});

it('uses the sole registered redirect when redirect_uri is omitted', function () {
    $parameters = validAuthorizationParameters();
    unset($parameters['redirect_uri']);
    $result = authorizationValidator()->validate($parameters);

    expect($result->error)->toBeNull()
        ->and($result->acceptedRequest()->redirectUri)->toBe('https://client.example/callback');
});
