<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationAudienceResolverInterface;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;

function authorizationClient(array $audiences = ['orders-api']): OAuthClient
{
    return new OAuthClient(
        clientId: 'client-1',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: ['read', 'openid'],
        audiences: $audiences,
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
}

function authorizationValidator(?OAuthAuthorizationAudienceResolverInterface $resolver = null): OAuthAuthorizationRequestValidator
{
    $store = new InMemoryOAuthClientStore([authorizationClient()]);

    return $resolver === null
        ? new OAuthAuthorizationRequestValidator($store)
        : new OAuthAuthorizationRequestValidator($store, $resolver);
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

it('accepts an exact authorization-code request with S256 PKCE and one resource audience', function () {
    $result = authorizationValidator()->validate(validAuthorizationParameters());

    expect($result->error)->toBeNull()
        ->and($result->acceptedRequest()->clientId)->toBe('client-1')
        ->and($result->acceptedRequest()->redirectUri)->toBe('https://client.example/callback')
        ->and($result->acceptedRequest()->scopes)->toBe(['read'])
        ->and($result->acceptedRequest()->audiences)->toBe(['orders-api'])
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

it('requires an explicit audience resolver for a multi-resource client', function () {
    $client = authorizationClient(['orders-api', 'billing-api']);
    $validator = new OAuthAuthorizationRequestValidator(new InMemoryOAuthClientStore([$client]));
    $result = $validator->validate(validAuthorizationParameters());

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->mayRedirect())->toBeTrue();
});

it('accepts an explicit registered audience resolution for a multi-resource client', function () {
    $client = authorizationClient(['orders-api', 'billing-api']);
    $resolver = new class implements OAuthAuthorizationAudienceResolverInterface {
        public function resolve(OAuthClient $client, array $scopes): array
        {
            return ['billing-api'];
        }
    };
    $validator = new OAuthAuthorizationRequestValidator(new InMemoryOAuthClientStore([$client]), $resolver);
    $result = $validator->validate(validAuthorizationParameters());

    expect($result->error)->toBeNull()
        ->and($result->acceptedRequest()->audiences)->toBe(['billing-api']);
});

it('rejects an audience resolver that expands beyond client registration', function () {
    $resolver = new class implements OAuthAuthorizationAudienceResolverInterface {
        public function resolve(OAuthClient $client, array $scopes): array
        {
            return ['attacker-api'];
        }
    };
    $result = authorizationValidator($resolver)->validate(validAuthorizationParameters());

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->redirectUri)->toBe('https://client.example/callback');
});
