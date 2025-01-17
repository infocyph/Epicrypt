<?php

# Symmetric
test('aes-256-gcm binary', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('aes-256-gcm', true, true);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('aes-256-gcm encoded', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('aes-256-gcm', false, false);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('chacha20-poly1305 binary', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('chacha20-poly1305', true, true);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('chacha20-poly1305 encoded', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('chacha20-poly1305', false, false);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('chacha20-poly1305-ietf binary', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('chacha20-poly1305-ietf', true, true);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('chacha20-poly1305-ietf encoded', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('chacha20-poly1305-ietf', false, false);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('xchacha20-poly1305-ietf binary', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('xchacha20-poly1305-ietf', true, true);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});

test('xchacha20-poly1305-ietf encoded', function () {
    $aead = new Infocyph\Epicrypt\Sodium\SodiumAead('xchacha20-poly1305-ietf', false, false);
    $secret = $aead->generateEncryptionKey();
    $nonce = $aead->generateNonce();
    expect($secret)->toBeString();
    expect($nonce)->toBeString();
    $encrypted = $aead->encrypt('someData', $secret, $nonce, 'additionalData');
    expect($encrypted)->toBeString();
    $decrypted = $aead->decrypt($encrypted, $secret, $nonce, 'additionalData');
    expect($decrypted)->toBeString();
    expect($decrypted)->toBe('someData');
});
