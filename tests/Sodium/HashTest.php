<?php

use Infocyph\Epicrypt\Sodium\SodiumFileHash;
use Infocyph\Epicrypt\Sodium\SodiumPasswordHash;
use Infocyph\Epicrypt\Sodium\SodiumStringHash;

test('File Hash - blake2B', function () {
    $fileHash = new SodiumFileHash('blake2b');
    $secret = $fileHash->generateSecret();
    $hash = $fileHash->generate(__FILE__, $secret);
    expect($fileHash->verify($hash, __FILE__, $secret))->toBeTrue();
});

test('String Hash - blake2B', function () {
    $string = random_bytes(64);
    $stringHash = new SodiumStringHash('blake2b');
    $secret = $stringHash->generateSecret();
    $hash = $stringHash->generate($string, $secret);
    expect($stringHash->verify($hash, $string, $secret))->toBeTrue();
});

test('String Hash - sip', function () {
    $string = random_bytes(64);
    $stringHash = new SodiumStringHash('sip');
    $secret = $stringHash->generateSecret();
    $hash = $stringHash->generate($string, $secret);
    expect($stringHash->verify($hash, $string, $secret))->toBeTrue();
});

test('Password Hash - argon2id', function () {
    $string = random_bytes(64);
    $pwdHash = new SodiumPasswordHash('argon2id');
    $hash = $pwdHash->generate($string);
    expect($pwdHash->verify($hash, $string))->toBeTrue();
});

test('Password Hash - scryptsalsa208sha256', function () {
    $string = random_bytes(64);
    $pwdHash = new SodiumPasswordHash('scryptsalsa208sha256');
    $hash = $pwdHash->generate($string);
    expect($pwdHash->verify($hash, $string))->toBeTrue();
});
