<?php

use Infocyph\Epicrypt\Security\ActionToken;
use Infocyph\Epicrypt\Security\CsrfTokenManager;
use Infocyph\Epicrypt\Security\EmailVerificationToken;
use Infocyph\Epicrypt\Security\KeyRotationHelper;
use Infocyph\Epicrypt\Security\PasswordResetToken;
use Infocyph\Epicrypt\Security\RememberToken;
use Infocyph\Epicrypt\Security\SignedUrl;
use Infocyph\Epicrypt\Security\SignedPayloadCodec;

it('signs and verifies urls', function () {
    $signedUrl = new SignedUrl('url-secret');
    $signed = $signedUrl->generate('https://example.com/download', ['file' => 'report'], time() + 300);

    expect($signedUrl->verify($signed))->toBeTrue();
    expect($signedUrl->verify($signed . 'tamper'))->toBeFalse();
});

it('issues and verifies csrf tokens', function () {
    $codec = new SignedPayloadCodec('csrf-secret');
    $manager = new CsrfTokenManager($codec, 60);

    $token = $manager->issueToken('session-1');

    expect($manager->verifyToken('session-1', $token))->toBeTrue();
    expect($manager->verifyToken('session-2', $token))->toBeFalse();
});

it('issues purpose-bound reset and action tokens', function () {
    $codec = new SignedPayloadCodec('token-secret');

    $passwordResetToken = new PasswordResetToken($codec, 600);
    $resetToken = $passwordResetToken->issue('user-1');
    expect($passwordResetToken->verify($resetToken, 'user-1'))->toBeTrue();

    $actionToken = new ActionToken($codec, 600);
    $actionTokenValue = $actionToken->issue('user-1', 'delete-account');
    expect($actionToken->verify($actionTokenValue, 'user-1', 'delete-account'))->toBeTrue();

    $emailVerification = new EmailVerificationToken($codec, 600);
    $emailToken = $emailVerification->issue('user-1', 'user@example.com');
    expect($emailVerification->verify($emailToken, 'user@example.com'))->toBeTrue();

    $rememberToken = new RememberToken($codec, 600);
    $rememberTokenValue = $rememberToken->issue('user-1', 'device-1');
    expect($rememberToken->verify($rememberTokenValue, 'user-1', 'device-1'))->toBeTrue();
});

it('verifies signatures across rotated key sets', function () {
    $rotation = new KeyRotationHelper();

    $keys = ['k1' => 'legacy-key', 'k2' => 'active-key'];
    $payload = 'important-payload';

    $signature = $rotation->sign($payload, 'k2', $keys);

    expect($rotation->verify($payload, $signature, $keys, 'k2'))->toBeTrue();
    expect($rotation->verify($payload, $signature, ['k1' => 'legacy-key'], 'k1'))->toBeFalse();
});
