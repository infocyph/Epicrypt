<?php

use AbmmHasan\SafeGuard\Generate\Random;
use AbmmHasan\SafeGuard\Symmetric\OpenSSL\StringCrypt;

$crypt = new StringCrypt('secret', '1234567890');
$string = Random::string();

test('Default settings', function () use ($crypt, $string) {
    $encrypted = $crypt->encrypt($string);
    $decrypted = $crypt->decrypt($encrypted);
    expect($decrypted)->toBe($string);
});

//test('Default settings', function () use ($crypt, $string) {
//    $encrypted = $crypt->encrypt($string);
//    $decrypted = $crypt->decrypt($encrypted);
//    expect($decrypted)->toBe($string);
//});
