<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeArtifact;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationApproval;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeConsumer;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeConsumeStatus;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeIssuer;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequest;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryAuthorizationCodeStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthAuthorizationStore;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Psr\Clock\ClockInterface;

function phaseDClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

/** @return array{OAuthAuthorizationCodeIssuer, OAuthAuthorizationCodeConsumer, InMemoryOAuthAuthorizationStore, ClockInterface, string} */
function phaseDCodeLifecycle(?InMemoryAuthorizationCodeStore $codeStore = null): array
{
    $clock = phaseDClock(1_700_000_000);
    $key = random_bytes(32);
    $ring = new KeyRing([
        new KeyRingEntry(
            'authorization-code-v1',
            $key,
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            issuer: 'https://issuer.example',
        ),
    ], $clock);
    $artifact = new AuthorizationCodeArtifact($ring, 'https://issuer.example', $clock);
    $authorizationStore = new InMemoryOAuthAuthorizationStore();
    $codeStore ??= new InMemoryAuthorizationCodeStore();
    $issuer = new OAuthAuthorizationCodeIssuer($authorizationStore, $codeStore, $artifact, $clock);
    $consumer = new OAuthAuthorizationCodeConsumer($artifact, $codeStore, $authorizationStore, $clock);
    $verifier = str_repeat('V', 43);

    return [$issuer, $consumer, $authorizationStore, $clock, $verifier];
}

function phaseDCodeRequest(string $verifier): OAuthAuthorizationRequest
{
    return new OAuthAuthorizationRequest(
        clientId: 'browser-client',
        redirectUri: 'https://client.example/callback',
        scopes: ['profile', 'orders:read'],
        audiences: ['orders-api'],
        codeChallenge: Base64Url::encode(hash('sha256', $verifier, true)),
        state: 'state-1',
    );
}

it('issues a stored JOSE authorization code and consumes it exactly once', function () {
    [$issuer, $consumer, $authorizations, , $verifier] = phaseDCodeLifecycle();
    $request = phaseDCodeRequest($verifier);
    $approval = new OAuthAuthorizationApproval(
        subject: 'user-42',
        scopes: ['orders:read'],
        authenticationTime: 1_699_999_900,
        authorizationLifetimeSeconds: 3_600,
        authenticationContext: 'urn:example:acr:mfa',
        authenticationMethods: ['pwd', 'otp'],
    );

    $issue = $issuer->issue($request, $approval, 300);
    $storedAuthorization = $authorizations->find($issue->code->authorizationId);

    expect(explode('.', $issue->token))->toHaveCount(5)
        ->and($issue->code->scopes)->toBe(['orders:read'])
        ->and($issue->code->audiences)->toBe(['orders-api'])
        ->and($issue->responseParameters())->toBe([
            'code' => $issue->token,
            'iss' => 'https://issuer.example',
            'state' => 'state-1',
        ])
        ->and($storedAuthorization?->subject)->toBe('user-42')
        ->and($storedAuthorization?->scopes)->toBe(['orders:read'])
        ->and($storedAuthorization?->audiences)->toBe(['orders-api']);

    $first = $consumer->consume(
        $issue->token,
        'browser-client',
        'https://client.example/callback',
        $verifier,
    );
    $second = $consumer->consume(
        $issue->token,
        'browser-client',
        'https://client.example/callback',
        $verifier,
    );

    expect($first->consumed)->toBeTrue()
        ->and($first->status)->toBe(OAuthAuthorizationCodeConsumeStatus::CONSUMED)
        ->and($first->authorization?->authorizationId)->toBe($issue->code->authorizationId)
        ->and($second->consumed)->toBeFalse()
        ->and($second->status)->toBe(OAuthAuthorizationCodeConsumeStatus::REPLAYED);
});

it('does not consume an authorization code when client redirect or PKCE binding is wrong', function () {
    [$issuer, $consumer, , , $verifier] = phaseDCodeLifecycle();
    $issue = $issuer->issue(
        phaseDCodeRequest($verifier),
        new OAuthAuthorizationApproval('user-42', ['orders:read'], 1_699_999_900, 3_600),
    );

    expect($consumer->consume(
        $issue->token,
        'other-client',
        'https://client.example/callback',
        $verifier,
    )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::CLIENT_MISMATCH)
        ->and($consumer->consume(
            $issue->token,
            'browser-client',
            'https://client.example/other',
            $verifier,
        )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::REDIRECT_MISMATCH)
        ->and($consumer->consume(
            $issue->token,
            'browser-client',
            'https://client.example/callback',
            str_repeat('W', 43),
        )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::PKCE_MISMATCH)
        ->and($consumer->consume(
            $issue->token,
            'browser-client',
            'https://client.example/callback',
            $verifier,
        )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::CONSUMED);
});

it('rejects a code when its authoritative authorization has been revoked', function () {
    [$issuer, $consumer, $authorizations, $clock, $verifier] = phaseDCodeLifecycle();
    $issue = $issuer->issue(
        phaseDCodeRequest($verifier),
        new OAuthAuthorizationApproval('user-42', ['orders:read'], 1_699_999_900, 3_600),
    );

    $authorizations->revoke($issue->code->authorizationId, $clock->now()->getTimestamp());

    expect($consumer->consume(
        $issue->token,
        'browser-client',
        'https://client.example/callback',
        $verifier,
    )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::AUTHORIZATION_INACTIVE);
});

it('retries authorization-code uniqueness conflicts within the bounded storage budget', function () {
    [$issuer, $consumer, , , $verifier] = phaseDCodeLifecycle(new InMemoryAuthorizationCodeStore(2));
    $issue = $issuer->issue(
        phaseDCodeRequest($verifier),
        new OAuthAuthorizationApproval('user-42', ['orders:read'], 1_699_999_900, 3_600),
    );

    expect($consumer->consume(
        $issue->token,
        'browser-client',
        'https://client.example/callback',
        $verifier,
    )->status)->toBe(OAuthAuthorizationCodeConsumeStatus::CONSUMED);
});

it('fails closed when authorization-code uniqueness conflicts exhaust the retry budget', function () {
    [$issuer, , , , $verifier] = phaseDCodeLifecycle(new InMemoryAuthorizationCodeStore(3));

    expect(fn () => $issuer->issue(
        phaseDCodeRequest($verifier),
        new OAuthAuthorizationApproval('user-42', ['orders:read'], 1_699_999_900, 3_600),
    ))->toThrow(ConfigurationException::class, 'Unable to persist a unique OAuth authorization code.');
});
