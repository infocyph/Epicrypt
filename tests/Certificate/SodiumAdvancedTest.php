<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Sodium\SessionKeyExchange;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Crypto\Ristretto255;
use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

it('derives role-safe directional crypto_kx session keys', function () {
    $exchange = new SessionKeyExchange();
    $client = $exchange->generateKeyPair();
    $server = $exchange->generateKeyPair();
    $clientKeys = $exchange->clientSessionKeys($client, sodium_crypto_kx_publickey($server));
    $serverKeys = $exchange->serverSessionKeys($server, sodium_crypto_kx_publickey($client));

    expect($clientKeys->transmitKey)->toBe($serverKeys->receiveKey)
        ->and($clientKeys->receiveKey)->toBe($serverKeys->transmitKey)
        ->and($clientKeys->receiveKey)->not->toBe($clientKeys->transmitKey);
});

it('exposes validated advanced Ristretto255 operations', function () {
    $ristretto = new Ristretto255();
    $scalar = $ristretto->randomScalar();
    $point = $ristretto->multiplyBase($scalar);
    $same = $ristretto->add($point, $ristretto->subtract($point, $point));

    expect($ristretto->isValidPoint($point))->toBeTrue()
        ->and($same)->toBe($point)
        ->and(fn() => $ristretto->multiplyBase('short'))->toThrow(InvalidKeyException::class);
});

it('round trips AEGIS when available and otherwise fails without downgrading', function (AeadAlgorithm $algorithm) {
    $cipher = new AeadCipher($algorithm);
    if (getenv('EPICRYPT_REQUIRE_AEGIS') === '1') {
        expect($algorithm->isAvailable())->toBeTrue();
    }
    if ($algorithm->isAvailable()) {
        $key = random_bytes($algorithm->keyLength());
        $nonce = str_repeat("\xA5", $algorithm->nonceLength());
        $payload = $cipher->encryptWithBinaryKey('message', $key, 'context', nonce: $nonce);
        expect($cipher->decryptWithBinaryKey($payload, $key, 'context'))->toBe('message')
            ->and($cipher->encryptWithBinaryKey('message', $key, 'context', nonce: $nonce))->toBe($payload)
            ->and(fn() => $cipher->decryptWithBinaryKey($payload, $key, 'wrong-context'))
            ->toThrow(DecryptionException::class);

        return;
    }

    expect(fn() => $cipher->encryptWithBinaryKey('message', random_bytes($algorithm->keyLength())))
        ->toThrow(CryptoException::class, $algorithm->value . ' is not available');
})->with([AeadAlgorithm::AEGIS_128L, AeadAlgorithm::AEGIS_256]);
