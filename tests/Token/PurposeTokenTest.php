<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Payload\PurposeToken;
use Infocyph\Epicrypt\Token\Payload\PurposeTokenFailureReason;
use Psr\Clock\ClockInterface;

function purposeTokenClock(int $timestamp = 1_000): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

it('issues Foundation-friendly purpose tokens with typed metadata', function () {
    $clock = purposeTokenClock();
    $tokens = new PurposeToken(
        str_repeat('s', 64),
        'password_reset',
        'foundation.auth',
        900,
        $clock,
    );

    $token = $tokens->issue(
        ['ctx' => ['request_id' => 'req-1']],
        subjectId: 'account-1',
    );
    $result = $tokens->verify($token);

    expect($result->verified)->toBeTrue()
        ->and($result->failureReason)->toBeNull()
        ->and($result->subjectId)->toBe('account-1')
        ->and($result->tokenId)->toBeString()->toHaveLength(48)
        ->and($result->issuedAt)->toBe(1_000)
        ->and($result->expiresAt)->toBe(1_900)
        ->and($result->claims)->toBe(['ctx' => ['request_id' => 'req-1']])
        ->and($result->matchedKeyId)->toBeNull()
        ->and($result->usedFallbackKey)->toBeFalse();
});

it('covers Foundation passwordless and email verification claim mappings without a parallel HMAC codec', function () {
    $clock = purposeTokenClock();
    $secret = str_repeat('f', 64);

    $passwordless = new PurposeToken($secret, 'passwordless', 'foundation.auth', 600, $clock);
    $passwordlessResult = $passwordless->verify($passwordless->issue(
        ['ctx' => ['device_id' => 'browser-1']],
        subjectId: 'user@example.test',
    ));

    $email = new PurposeToken($secret, 'email_verification', 'foundation.auth', 600, $clock);
    $emailResult = $email->verify($email->issue(
        ['email' => 'user@example.test', 'ctx' => ['request_id' => 'req-2']],
        subjectId: 'account-2',
    ));

    expect($passwordlessResult->verified)->toBeTrue()
        ->and($passwordlessResult->subjectId)->toBe('user@example.test')
        ->and($passwordlessResult->claims)->toBe(['ctx' => ['device_id' => 'browser-1']])
        ->and($emailResult->verified)->toBeTrue()
        ->and($emailResult->subjectId)->toBe('account-2')
        ->and($emailResult->claims)->toBe([
            'email' => 'user@example.test',
            'ctx' => ['request_id' => 'req-2'],
        ]);
});

it('returns stable purpose, context, expiry, and not-before failures', function () {
    $clock = purposeTokenClock();
    $secret = str_repeat('x', 64);
    $issuer = new PurposeToken($secret, 'password_reset', 'foundation.auth', 900, $clock);

    $token = $issuer->issue(subjectId: 'account-1');

    expect((new PurposeToken($secret, 'email_verification', 'foundation.auth', 900, $clock))->verify($token)->failureReason)
        ->toBe(PurposeTokenFailureReason::WRONG_PURPOSE)
        ->and((new PurposeToken($secret, 'password_reset', 'other.auth', 900, $clock))->verify($token)->failureReason)
        ->toBe(PurposeTokenFailureReason::WRONG_CONTEXT);

    $future = $issuer->issue(subjectId: 'account-1', notBefore: 1_100);
    $futureResult = $issuer->verify($future);
    expect($futureResult->verified)->toBeFalse()
        ->and($futureResult->failureReason)->toBe(PurposeTokenFailureReason::NOT_YET_VALID)
        ->and($futureResult->notBefore)->toBe(1_100)
        ->and($futureResult->expiresAt)->toBe(1_900);

    $clock->timestamp = 1_900;
    $expiredResult = $issuer->verify($token);
    expect($expiredResult->verified)->toBeFalse()
        ->and($expiredResult->failureReason)->toBe(PurposeTokenFailureReason::EXPIRED_TOKEN)
        ->and($expiredResult->subjectId)->toBe('account-1')
        ->and($expiredResult->tokenId)->toBeString()
        ->and($expiredResult->expiresAt)->toBe(1_900);
});

it('uses signed key ids for constant-candidate KeyRing rotation', function () {
    $clock = purposeTokenClock();
    $oldKey = str_repeat('o', 64);
    $newKey = str_repeat('n', 64);

    $initial = new KeyRing([
        new KeyRingEntry('signed-2026-a', $oldKey, KeyStatus::ACTIVE, KeyPurpose::SIGNED_PAYLOAD, 'sha512'),
    ], $clock);
    $oldIssuer = new PurposeToken($initial, 'password_reset', 'foundation.auth', 900, $clock);
    $oldToken = $oldIssuer->issue(subjectId: 'account-1');

    $rotated = new KeyRing([
        new KeyRingEntry('signed-2026-a', $oldKey, KeyStatus::FALLBACK, KeyPurpose::SIGNED_PAYLOAD, 'sha512'),
        new KeyRingEntry('signed-2026-b', $newKey, KeyStatus::ACTIVE, KeyPurpose::SIGNED_PAYLOAD, 'sha512'),
    ], $clock);
    $tokens = new PurposeToken($rotated, 'password_reset', 'foundation.auth', 900, $clock);

    $oldResult = $tokens->verify($oldToken);
    $newResult = $tokens->verify($tokens->issue(subjectId: 'account-2'));

    expect($oldResult->verified)->toBeTrue()
        ->and($oldResult->matchedKeyId)->toBe('signed-2026-a')
        ->and($oldResult->usedFallbackKey)->toBeTrue()
        ->and($newResult->verified)->toBeTrue()
        ->and($newResult->matchedKeyId)->toBe('signed-2026-b')
        ->and($newResult->usedFallbackKey)->toBeFalse();
});

it('rejects unknown rotation keys, tampering, and reserved caller claims', function () {
    $clock = purposeTokenClock();
    $ring = new KeyRing([
        new KeyRingEntry('signed-a', str_repeat('a', 64), KeyStatus::ACTIVE, KeyPurpose::SIGNED_PAYLOAD, 'sha512'),
    ], $clock);
    $tokens = new PurposeToken($ring, 'password_reset', 'foundation.auth', 900, $clock);
    $token = $tokens->issue(subjectId: 'account-1');

    $parts = explode('.', $token);
    $parts[2] = str_repeat('A', strlen($parts[2]));
    $tampered = implode('.', $parts);

    expect($tokens->verify($tampered)->failureReason)->toBe(PurposeTokenFailureReason::INVALID_TOKEN)
        ->and(fn() => $tokens->issue(['purpose' => 'email_verification']))
        ->toThrow(ConfigurationException::class);
});
