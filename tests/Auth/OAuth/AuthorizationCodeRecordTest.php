<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeRecord;
use Psr\Clock\ClockInterface;

it('derives a stable authoritative record from the authenticated authorization code state', function () {
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable { return new DateTimeImmutable('@1700000000'); }
    };
    $code = AuthorizationCode::issue(
        issuer: 'https://issuer.example',
        authorizationId: 'authorization-1',
        subject: 'user-1',
        clientId: 'client-1',
        redirectUri: 'https://client.example/callback',
        pkceChallenge: str_repeat('A', 43),
        scopes: ['orders:read'],
        audiences: ['orders-api'],
        clock: $clock,
    );

    $first = AuthorizationCodeRecord::fromCode($code);
    $second = AuthorizationCodeRecord::fromCode($code);
    expect($first->sameState($second))->toBeTrue()
        ->and($first->codeId)->toBe($code->codeId)
        ->and($first->authorizationId)->toBe('authorization-1')
        ->and($first->expiresAt)->toBe(1_700_000_300)
        ->and($first->stateDigest)->toMatch('/\A[a-f0-9]{64}\z/D');
});
