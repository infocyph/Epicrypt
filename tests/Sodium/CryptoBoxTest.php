<?php

# Asymmetric
use Infocyph\Epicrypt\Sodium\SodiumCryptoBox;

$party1 = new SodiumCryptoBox();
$party2 = new SodiumCryptoBox();
$party1Secret = $party1->generateSecretPair();
$party2Secret = $party2->generateSecretPair();
$shared = $party1->generateSharedSecret(); // either party's shared key
$message = 'message';

test('Party1 to Party2', function () use ($party1Secret, $party2Secret, $message, $party1, $party2, $shared) {
    $encrypted = $party1->encrypt($message, $party2Secret['public'], $party1Secret['private'], $shared);
    $decrypted = $party2->decrypt($encrypted, $party1Secret['public'], $party2Secret['private'], $shared);
    expect($decrypted)->toBe($message);
});

test('Party2 to Party1', function () use ($party1Secret, $party2Secret, $message, $party1, $party2, $shared) {
    $encrypted = $party2->encrypt($message, $party1Secret['public'], $party2Secret['private'], $shared);
    $decrypted = $party1->decrypt($encrypted, $party2Secret['public'], $party1Secret['private'], $shared);
    expect($decrypted)->toBe($message);
});

unset($party1, $party2, $party1Secret, $party2Secret, $shared, $message);
