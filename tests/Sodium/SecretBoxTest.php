<?php

# Symmetric
test('binary', function () {
    $authenticity = new Infocyph\Epicrypt\Sodium\SodiumSecretBox(true, true);
    $nonce = $authenticity->generateNonce();
    $secret = $authenticity->generateSecret();
    $message = 'message';
    $encrypted = $authenticity->encrypt($message, $secret, $nonce);
    expect($authenticity->decrypt($encrypted, $secret, $nonce))->toBe($message);
});

test('encoded', function () {
    $authenticity = new Infocyph\Epicrypt\Sodium\SodiumSecretBox(false, false);
    $nonce = $authenticity->generateNonce();
    $secret = $authenticity->generateSecret();
    $message = 'message';
    $encrypted = $authenticity->encrypt($message, $secret, $nonce);
    expect($authenticity->decrypt($encrypted, $secret, $nonce))->toBe($message);
});
