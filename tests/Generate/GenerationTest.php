<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\HkdfAlgorithm;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('generates secure material and derives deterministic keys', function () {
    expect((new RandomBytesGenerator())->bytes(32))->not->toBe((new RandomBytesGenerator())->bytes(32))
        ->and((new NonceGenerator())->generate())->not->toBe('')
        ->and((new SaltGenerator())->generate())->not->toBe('')
        ->and((new KeyMaterialGenerator())->forAead())->not->toBe('');

    $input = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $deriver = new KeyDeriver();
    expect($deriver->hkdf($input, 32, HkdfAlgorithm::SHA512, 'application-purpose:v1'))
        ->toBe($deriver->hkdf($input, 32, HkdfAlgorithm::SHA512, 'application-purpose:v1'));
});

it('honors exact random string lengths including affixes', function () {
    $random = new RandomBytesGenerator();

    expect(strlen($random->string(32)))->toBe(32)
        ->and(strlen($random->string(32, prefix: 'pre-')))->toBe(32)
        ->and(strlen($random->string(32, postfix: '-post')))->toBe(32)
        ->and(strlen($random->string(32, prefix: 'pre-', postfix: '-post')))->toBe(32)
        ->and(fn () => $random->string(8, prefix: '1234', postfix: '5678'))
        ->toThrow(ConfigurationException::class);
});

it('matches the RFC 5869 SHA-256 vector and supports every curated HKDF hash', function () {
    $deriver = new KeyDeriver();
    $ikm = hex2bin(str_repeat('0b', 22));
    $salt = hex2bin('000102030405060708090a0b0c');
    $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
    $expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

    expect(bin2hex($deriver->hkdfBinary($ikm, 42, HkdfAlgorithm::SHA256, $info, $salt)))
        ->toBe($expected);

    foreach (HkdfAlgorithm::cases() as $algorithm) {
        $encodedIkm = sodium_bin2base64($ikm, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $encodedSalt = sodium_bin2base64($salt, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $encoded = $deriver->hkdf($encodedIkm, 32, $algorithm, 'purpose/v1', $encodedSalt);
        $binary = $deriver->hkdfBinary($ikm, 32, $algorithm, 'purpose/v1', $salt);
        expect(sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))->toBe($binary);
    }
});

it('keeps subkey and password KDF binary and encoded APIs equivalent', function () {
    $deriver = new KeyDeriver();
    $root = random_bytes(SODIUM_CRYPTO_KDF_KEYBYTES);
    $encodedRoot = sodium_bin2base64($root, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $encodedSalt = sodium_bin2base64($salt, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

    $encodedSubkey = $deriver->subkey($encodedRoot, 7, 'TESTKDF1', 32);
    expect(sodium_base642bin($encodedSubkey, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))
        ->toBe($deriver->subkeyBinary($root, 7, 'TESTKDF1', 32));

    $encodedPasswordKey = $deriver->deriveFromPassword(
        'correct horse battery staple',
        $encodedSalt,
        opslimit: SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        memlimit: SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    );
    $binaryPasswordKey = $deriver->deriveBinaryFromPassword(
        'correct horse battery staple',
        $salt,
        opslimit: SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        memlimit: SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    );
    expect(sodium_base642bin($encodedPasswordKey, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))
        ->toBe($binaryPasswordKey)
        ->and(fn () => $deriver->subkeyBinary($root, 1, 'SHORT', 32))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $deriver->deriveBinaryFromPassword('password', random_bytes(15)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $deriver->deriveBinaryFromPassword('password', $salt, opslimit: 0))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $deriver->deriveBinaryFromPassword('password', $salt, memlimit: 1))
        ->toThrow(ConfigurationException::class);
});
