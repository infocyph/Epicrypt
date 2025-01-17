<?php

# Symmetric
test('binary', function () {
    $authenticity = new Infocyph\Epicrypt\Sodium\SodiumAuth(true, true);
    $message = 'message';
    $secret = $authenticity->generateSecret();
    $signature = $authenticity->compute($message, $secret);
    expect($authenticity->verify($message, $secret, $signature))->toBeTrue();
});

test('encoded', function () {
    $authenticity = new Infocyph\Epicrypt\Sodium\SodiumAuth(false, false);
    $message = 'message';
    $secret = $authenticity->generateSecret();
    $signature = $authenticity->compute($message, $secret);
    expect($authenticity->verify($message, $secret, $signature))->toBeTrue();
});
