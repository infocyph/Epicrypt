<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationApproval;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationInteraction;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationInteractionRequirement;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequest;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationResult;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;

function phaseDAuthorizationClient(): OAuthClient
{
    return new OAuthClient(
        clientId: 'browser-client',
        type: OAuthClientType::PUBLIC,
        enabled: true,
        redirectUris: ['https://client.example/callback'],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::REFRESH_TOKEN],
        scopes: ['profile', 'orders:read'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
}

function phaseDAuthorizationRequest(): OAuthAuthorizationRequest
{
    return new OAuthAuthorizationRequest(
        clientId: 'browser-client',
        redirectUri: 'https://client.example/callback',
        scopes: ['profile', 'orders:read'],
        audiences: ['orders-api'],
        codeChallenge: str_repeat('A', 43),
        state: 'state-1',
    );
}

it('represents authentication and authorization decision as typed interactions', function () {
    $request = phaseDAuthorizationRequest();
    $client = phaseDAuthorizationClient();
    $result = OAuthAuthorizationResult::accepted($request, $client);

    $authentication = $result->interaction();
    $decision = OAuthAuthorizationInteraction::authorizationDecisionRequired(
        $request,
        $client,
        'user-42',
        1_700_000_000,
        'urn:example:acr:mfa',
        ['pwd', 'otp'],
    );
    $approval = OAuthAuthorizationApproval::fromInteraction(
        $decision,
        ['orders:read'],
        3_600,
    );
    $denial = $decision->accessDenied();

    expect($authentication->requirement)->toBe(OAuthAuthorizationInteractionRequirement::SUBJECT_AUTHENTICATION)
        ->and($authentication->subject)->toBeNull()
        ->and($decision->requirement)->toBe(OAuthAuthorizationInteractionRequirement::AUTHORIZATION_DECISION)
        ->and($decision->subject)->toBe('user-42')
        ->and($approval->scopes)->toBe(['orders:read'])
        ->and($approval->authenticationMethods)->toBe(['pwd', 'otp'])
        ->and($approval->authorizationLifetimeSeconds)->toBe(3_600)
        ->and($denial->code)->toBe(OAuthErrorCode::ACCESS_DENIED)
        ->and($denial->redirectUri)->toBe('https://client.example/callback')
        ->and($denial->responseParameters('https://issuer.example'))->toBe([
            'error' => 'access_denied',
            'iss' => 'https://issuer.example',
            'state' => 'state-1',
        ]);
});
