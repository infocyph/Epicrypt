<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationAudienceResolverInterface;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthProtocolError;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;

function phaseDSecurityClient(
    bool $enabled = true,
    array $redirectUris = ['https://client.example/callback'],
    array $grantTypes = [OAuthGrantType::AUTHORIZATION_CODE],
): OAuthClient {
    return new OAuthClient(
        clientId: 'security-client',
        type: OAuthClientType::PUBLIC,
        enabled: $enabled,
        redirectUris: $redirectUris,
        grantTypes: $grantTypes,
        scopes: ['read', 'write'],
        audiences: ['orders-api'],
        authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );
}

/** @return array<string, string|list<string>> */
function phaseDSecurityParameters(): array
{
    return [
        'client_id' => 'security-client',
        'redirect_uri' => 'https://client.example/callback',
        'response_type' => 'code',
        'scope' => 'read',
        'state' => 'state-1',
        'code_challenge' => str_repeat('A', 43),
        'code_challenge_method' => 'S256',
    ];
}

function phaseDSecurityValidator(OAuthClient $client): OAuthAuthorizationRequestValidator
{
    return new OAuthAuthorizationRequestValidator(new InMemoryOAuthClientStore([$client]));
}

it('never redirects unknown disabled or mismatched clients to request-controlled locations', function () {
    $unknown = phaseDSecurityParameters();
    $unknown['client_id'] = 'unknown-client';

    $disabled = phaseDSecurityParameters();

    $mismatch = phaseDSecurityParameters();
    $mismatch['redirect_uri'] = 'https://attacker.example/callback';

    expect(phaseDSecurityValidator(phaseDSecurityClient())->validate($unknown)->error?->mayRedirect())->toBeFalse()
        ->and(phaseDSecurityValidator(phaseDSecurityClient(false))->validate($disabled)->error?->mayRedirect())->toBeFalse()
        ->and(phaseDSecurityValidator(phaseDSecurityClient())->validate($mismatch)->error?->mayRedirect())->toBeFalse();
});

it('rejects omitted ambiguous redirect and unsupported response types safely', function () {
    $ambiguous = phaseDSecurityParameters();
    unset($ambiguous['redirect_uri']);
    $ambiguousClient = phaseDSecurityClient(
        redirectUris: [
            'https://client.example/callback',
            'https://client.example/alternate',
        ],
    );

    $unsupported = phaseDSecurityParameters();
    $unsupported['response_type'] = 'token';
    $unsupportedResult = phaseDSecurityValidator(phaseDSecurityClient())->validate($unsupported);

    expect(phaseDSecurityValidator($ambiguousClient)->validate($ambiguous)->error?->mayRedirect())->toBeFalse()
        ->and($unsupportedResult->error?->code)->toBe(OAuthErrorCode::UNSUPPORTED_RESPONSE_TYPE)
        ->and($unsupportedResult->error?->redirectUri)->toBe('https://client.example/callback')
        ->and($unsupportedResult->error?->state)->toBe('state-1');
});

it('requires issuer identification when serializing a redirectable authorization error', function () {
    $error = new OAuthProtocolError(
        OAuthErrorCode::INVALID_REQUEST,
        'https://client.example/callback',
        'state-1',
    );

    expect(fn() => $error->responseParameters())->toThrow(ConfigurationException::class)
        ->and($error->responseParameters('https://issuer.example'))->toBe([
            'error' => 'invalid_request',
            'iss' => 'https://issuer.example',
            'state' => 'state-1',
        ])
        ->and((new OAuthProtocolError(OAuthErrorCode::INVALID_REQUEST))->responseParameters())->toBe([
            'error' => 'invalid_request',
        ]);
});

it('rejects malformed PKCE duplicated scope and invalid state after establishing the registered redirect', function () {
    $badPkce = phaseDSecurityParameters();
    $badPkce['code_challenge'] = 'short';

    $duplicateScope = phaseDSecurityParameters();
    $duplicateScope['scope'] = 'read read';

    $badState = phaseDSecurityParameters();
    $badState['state'] = '';

    $validator = phaseDSecurityValidator(phaseDSecurityClient());

    expect($validator->validate($badPkce)->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($validator->validate($duplicateScope)->error?->code)->toBe(OAuthErrorCode::INVALID_SCOPE)
        ->and($validator->validate($badState)->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($validator->validate($badState)->error?->state)->toBeNull();
});

it('rejects duplicate singleton parameters without redirecting', function () {
    $parameters = phaseDSecurityParameters();
    $parameters['redirect_uri'] = [
        'https://client.example/callback',
        'https://attacker.example/callback',
    ];

    $result = phaseDSecurityValidator(phaseDSecurityClient())->validate($parameters);

    expect($result->error?->code)->toBe(OAuthErrorCode::INVALID_REQUEST)
        ->and($result->error?->mayRedirect())->toBeFalse();
});

it('contains audience resolver failures within an already validated redirect', function () {
    $resolver = new class implements OAuthAuthorizationAudienceResolverInterface {
        public function resolve(OAuthClient $client, array $scopes): array
        {
            if (!$client->enabled || $scopes !== ['read']) {
                throw new LogicException('Audience resolver received unvalidated request state.');
            }

            throw new RuntimeException('adapter failure');
        }
    };
    $validator = new OAuthAuthorizationRequestValidator(
        new InMemoryOAuthClientStore([phaseDSecurityClient()]),
        $resolver,
    );
    $result = $validator->validate(phaseDSecurityParameters());

    expect($result->error?->code)->toBe(OAuthErrorCode::SERVER_ERROR)
        ->and($result->error?->redirectUri)->toBe('https://client.example/callback')
        ->and($result->error?->state)->toBe('state-1');
});
