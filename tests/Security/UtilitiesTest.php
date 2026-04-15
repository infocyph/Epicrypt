<?php

use Infocyph\Epicrypt\Security\ActionToken\ActionTokenIssuer;
use Infocyph\Epicrypt\Security\ActionToken\ActionTokenVerifier;
use Infocyph\Epicrypt\Security\Csrf\CsrfTokenManager;
use Infocyph\Epicrypt\Security\KeyRotation\KeyRotationHelper;
use Infocyph\Epicrypt\Security\PasswordReset\PasswordResetTokenIssuer;
use Infocyph\Epicrypt\Security\PasswordReset\PasswordResetTokenVerifier;
use Infocyph\Epicrypt\Security\SignedUrl\SignedUrlGenerator;
use Infocyph\Epicrypt\Security\SignedUrl\SignedUrlVerifier;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

it('signs and verifies urls', function () {
    $generator = new SignedUrlGenerator('url-secret');
    $verifier = new SignedUrlVerifier('url-secret');

    $signed = $generator->generate('https://example.com/download', ['file' => 'report'], time() + 300);

    expect($verifier->verify($signed))->toBeTrue();
    expect($verifier->verify($signed . 'tamper'))->toBeFalse();
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

    $resetIssuer = new PasswordResetTokenIssuer($codec, 600);
    $resetVerifier = new PasswordResetTokenVerifier($codec);

    $resetToken = $resetIssuer->issue('user-1');
    expect($resetVerifier->verify($resetToken, 'user-1'))->toBeTrue();

    $actionIssuer = new ActionTokenIssuer($codec, 600);
    $actionVerifier = new ActionTokenVerifier($codec);

    $actionToken = $actionIssuer->issue('user-1', 'delete-account');
    expect($actionVerifier->verify($actionToken, 'user-1', 'delete-account'))->toBeTrue();
});

it('verifies signatures across rotated key sets', function () {
    $rotation = new KeyRotationHelper();

    $keys = ['k1' => 'legacy-key', 'k2' => 'active-key'];
    $payload = 'important-payload';

    $signature = $rotation->sign($payload, 'k2', $keys);

    expect($rotation->verify($payload, $signature, $keys, 'k2'))->toBeTrue();
    expect($rotation->verify($payload, $signature, ['k1' => 'legacy-key'], 'k1'))->toBeFalse();
});
