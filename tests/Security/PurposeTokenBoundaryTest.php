<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\ActionToken;
use Infocyph\Epicrypt\Security\CsrfTokenManager;
use Infocyph\Epicrypt\Security\EmailVerificationToken;
use Infocyph\Epicrypt\Security\PasswordResetToken;
use Infocyph\Epicrypt\Security\RememberToken;
use Psr\Clock\ClockInterface;

function purposeTokenClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@'.$this->timestamp);
        }
    };
}

it('enforces the shared secret floor and positive bounded TTLs', function () {
    expect(fn () => new ActionToken(str_repeat('s', 31)))
        ->toThrow(ConfigurationException::class)
        ->and(new ActionToken(str_repeat('s', 32)))
        ->toBeInstanceOf(ActionToken::class)
        ->and(fn () => new ActionToken(str_repeat('s', 32), 0))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new ActionToken(str_repeat('s', 32), 3601))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new CsrfTokenManager(str_repeat('s', 32), -1))
        ->toThrow(ConfigurationException::class);
});

it('requires every purpose-specific subject and action binding', function () {
    $secret = str_repeat('p', 32);
    $action = new ActionToken($secret);
    $reset = new PasswordResetToken($secret);
    $email = new EmailVerificationToken($secret);
    $remember = new RememberToken($secret);

    $actionToken = $action->issue('user-42', 'delete-account');
    $resetToken = $reset->issue('user-42');
    $emailToken = $email->issue('user-42', 'user@example.test');
    $rememberToken = $remember->issue('user-42', 'device-7');

    expect($action->verify($actionToken, 'user-42', 'delete-account'))->toBeTrue()
        ->and($action->verify($actionToken, 'user-42', 'change-email'))->toBeFalse()
        ->and($reset->verify($resetToken, 'user-41'))->toBeFalse()
        ->and($email->verify($emailToken, 'user-41', 'user@example.test'))->toBeFalse()
        ->and($email->verify($emailToken, 'user-42', 'other@example.test'))->toBeFalse()
        ->and($remember->verify($rememberToken, 'user-42', 'device-8'))->toBeFalse();
});

it('rejects invalid and oversized purpose-token identifiers', function () {
    $secret = str_repeat('p', 32);

    expect(fn () => new ActionToken($secret)->issue('', 'action'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new PasswordResetToken($secret)->issue("user\n42"))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new RememberToken($secret)->issue(str_repeat('u', 257), 'device'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new EmailVerificationToken($secret)->issue('user-42', 'invalid-email'))
        ->toThrow(ConfigurationException::class);
});

it('expires purpose and CSRF tokens at the exact expiration instant', function () {
    $clock = purposeTokenClock(1_700_000_000);
    $secret = str_repeat('p', 32);
    $action = new ActionToken($secret, 10, $clock);
    $csrf = new CsrfTokenManager($secret, 10, $clock);
    $actionToken = $action->issue('user-42', 'confirm');
    $csrfToken = $csrf->issueToken('session-42');

    expect($action->verify($actionToken, 'user-42', 'confirm'))->toBeTrue()
        ->and($csrf->verifyToken('session-42', $csrfToken))->toBeTrue();

    $clock->timestamp += 10;

    expect($action->verify($actionToken, 'user-42', 'confirm'))->toBeFalse()
        ->and($csrf->verifyToken('session-42', $csrfToken))->toBeFalse();
});
