<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdInteractionErrorCode;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdInteractionPolicy;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdInteractionRequirement;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdInteractionState;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdPrompt;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;
use Psr\Clock\ClockInterface;

function oidcPhaseFClient(): OAuthClient
{
    return new OAuthClient(
        clientId: 'oidc-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example.test/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        scopes: ['openid', 'profile'],
        audiences: ['https://api.example.test'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
}

function oidcPhaseFValidator(): OpenIdAuthorizationRequestValidator
{
    return new OpenIdAuthorizationRequestValidator(
        new OAuthAuthorizationRequestValidator(new InMemoryOAuthClientStore([oidcPhaseFClient()])),
    );
}

/** @return array<string, string|list<string>> */
function oidcPhaseFParameters(string $scope = 'openid profile'): array
{
    return [
        'client_id' => 'oidc-client',
        'redirect_uri' => 'https://client.example.test/callback',
        'response_type' => 'code',
        'scope' => $scope,
        'state' => 'oidc-state',
        'code_challenge' => str_repeat('A', 43),
        'code_challenge_method' => 'S256',
    ];
}

it('activates OpenID Connect only for the exact openid scope and parses request extensions', function () {
    $parameters = oidcPhaseFParameters();
    $parameters['nonce'] = 'nonce-1';
    $parameters['prompt'] = 'login';
    $parameters['max_age'] = '300';
    $parameters['acr_values'] = 'urn:example:loa2 urn:example:loa1';

    $result = oidcPhaseFValidator()->validate($parameters);

    expect($result->accepted())->toBeTrue()
        ->and($result->isOpenId())->toBeTrue()
        ->and($result->requireOpenId()->nonce)->toBe('nonce-1')
        ->and($result->requireOpenId()->prompts)->toBe([OpenIdPrompt::LOGIN])
        ->and($result->requireOpenId()->maximumAuthenticationAge)->toBe(300)
        ->and($result->requireOpenId()->acrValues)->toBe(['urn:example:loa2', 'urn:example:loa1']);

    $oauthOnly = oidcPhaseFValidator()->validate(oidcPhaseFParameters('profile'));
    expect($oauthOnly->accepted())->toBeTrue()
        ->and($oauthOnly->isOpenId())->toBeFalse();
});

it('rejects invalid or duplicate OIDC singleton parameters after establishing a safe redirect', function () {
    $parameters = oidcPhaseFParameters();
    $parameters['prompt'] = 'none login';
    $result = oidcPhaseFValidator()->validate($parameters);
    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->redirectUri)->toBe('https://client.example.test/callback');

    $parameters = oidcPhaseFParameters();
    $parameters['nonce'] = ['one', 'two'];
    expect(oidcPhaseFValidator()->validate($parameters)->error?->code)
        ->toBe(OAuthErrorCode::INVALID_REQUEST);
});

it('maps prompt none interaction failures to OIDC authorization errors', function () {
    $parameters = oidcPhaseFParameters();
    $parameters['prompt'] = 'none';
    $parameters['max_age'] = '60';
    $request = oidcPhaseFValidator()->validate($parameters)->requireOpenId();
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable { return new DateTimeImmutable('@1700000100'); }
    };
    $policy = new OpenIdInteractionPolicy($clock);

    expect($policy->evaluate($request, new OpenIdInteractionState())->error)
        ->toBe(OpenIdInteractionErrorCode::LOGIN_REQUIRED);

    $stale = new OpenIdInteractionState(
        subject: 'user-1',
        authenticationTime: 1_700_000_000,
        authenticationContext: 'urn:example:loa1',
        consentRequired: false,
    );
    expect($policy->evaluate($request, $stale)->error)
        ->toBe(OpenIdInteractionErrorCode::LOGIN_REQUIRED);
});

it('produces account-selection, consent, ACR reauthentication and ready requirements', function () {
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable { return new DateTimeImmutable('@1700000100'); }
    };
    $policy = new OpenIdInteractionPolicy($clock);
    $state = new OpenIdInteractionState(
        subject: 'user-1',
        authenticationTime: 1_700_000_090,
        authenticationContext: 'urn:example:loa2',
        authenticationMethods: ['pwd'],
        consentRequired: false,
    );

    $parameters = oidcPhaseFParameters();
    $parameters['prompt'] = 'select_account';
    $request = oidcPhaseFValidator()->validate($parameters)->requireOpenId();
    expect($policy->evaluate($request, $state)->requirement)
        ->toBe(OpenIdInteractionRequirement::ACCOUNT_SELECTION);

    $parameters = oidcPhaseFParameters();
    $parameters['prompt'] = 'consent';
    $request = oidcPhaseFValidator()->validate($parameters)->requireOpenId();
    expect($policy->evaluate($request, $state)->requirement)
        ->toBe(OpenIdInteractionRequirement::AUTHORIZATION_DECISION);

    $parameters = oidcPhaseFParameters();
    $parameters['acr_values'] = 'urn:example:loa3';
    $request = oidcPhaseFValidator()->validate($parameters)->requireOpenId();
    expect($policy->evaluate($request, $state)->requirement)
        ->toBe(OpenIdInteractionRequirement::SUBJECT_AUTHENTICATION);

    $request = oidcPhaseFValidator()->validate(oidcPhaseFParameters())->requireOpenId();
    expect($policy->evaluate($request, $state)->requirement)
        ->toBe(OpenIdInteractionRequirement::READY);
});
