<?php

# Anonymous Asymmetric

test('encoded', function () {
    $scs = new \Infocyph\Epicrypt\Sodium\SodiumCryptoSeal();
    $secretPair = $scs->generateSecretPair();
    $message = 'Hello World';
    $encrypted = $scs->encrypt($message, $secretPair['public']);
    $decrypted = $scs->decrypt($encrypted, $secretPair['keypair']);
    expect($decrypted)->toBe($message);
});
test('binary', function () {
    $scs = new \Infocyph\Epicrypt\Sodium\SodiumCryptoSeal(true, true);
    $secretPair = $scs->generateSecretPair();
    $message = 'Hello World';
    $encrypted = $scs->encrypt($message, $secretPair['public']);
    $decrypted = $scs->decrypt($encrypted, $secretPair['keypair']);
    expect($decrypted)->toBe($message);
});


