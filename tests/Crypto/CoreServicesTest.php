<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Mac;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Crypto\Signature;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('encrypts and decrypts with AEAD services', function () {
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

    $cipher = new AeadCipher;

    $ciphertext = $cipher->encrypt('epicrypt-aead', $key, 'meta');
    $segments = explode('.', $ciphertext);
    $plaintext = $cipher->decrypt($ciphertext, $key, 'meta');

    expect($ciphertext)->toStartWith('epc2.');
    expect($segments)->toHaveCount(4);
    expect($segments[1])->toBe('xchacha20-poly1305-ietf');
    expect($plaintext)->toBe('epicrypt-aead');
});

it('rejects tampered aead payload algorithm identifiers', function () {
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    $cipher = new AeadCipher;
    $ciphertext = $cipher->encrypt('epicrypt-aead', $key, 'meta');
    $segments = explode('.', $ciphertext);
    $segments[1] = 'unknown-algorithm';
    $tamperedCiphertext = implode('.', $segments);

    expect(fn () => $cipher->decrypt($tamperedCiphertext, $key, 'meta'))
        ->toThrow(DecryptionException::class);
});

it('rejects payload algorithms that do not match secretbox', function () {
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $cipher = new SecretBoxCipher;
    $ciphertext = $cipher->encrypt('epicrypt-secretbox', $key);
    $segments = explode('.', $ciphertext);
    $segments[1] = 'xchacha20-poly1305-ietf';
    $tamperedCiphertext = implode('.', $segments);

    expect(fn () => $cipher->decrypt($tamperedCiphertext, $key))
        ->toThrow(DecryptionException::class);
});

it('signs and verifies detached signatures', function () {
    $keys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);

    $signatureService = new Signature;
    $signature = $signatureService->sign('epicrypt-signature', $keys['private']);

    expect($signatureService->verify('epicrypt-signature', $signature, $keys['public']))->toBeTrue();
    expect($signatureService->verify('tampered', $signature, $keys['public']))->toBeFalse();
    expect($signatureService->verify('epicrypt-signature', 'invalid***', $keys['public']))->toBeFalse();
});

it('rejects invalid signature key material', function () {
    $signatureService = new Signature;

    expect(fn () => $signatureService->sign('epicrypt-signature', 'short-key'))
        ->toThrow(SignatureException::class);
    expect(fn () => $signatureService->verify('epicrypt-signature', 'invalid-sig', 'short-key'))
        ->toThrow(SignatureException::class);
});

it('generates and verifies mac tags', function () {
    $macService = new Mac;
    $key = $macService->generateKey();
    $mac = $macService->generate('epicrypt-mac', $key);

    expect($macService->verify('epicrypt-mac', $mac, $key))->toBeTrue();
    expect($macService->verify('wrong', $mac, $key))->toBeFalse();
    expect($macService->verify('epicrypt-mac', 'invalid***', $key))->toBeFalse();
});

it('rejects malformed encoded and binary MAC keys with stable error taxonomy', function () {
    $macService = new Mac;

    expect(fn () => $macService->generateWithBinaryKey('message', 'short'))
        ->toThrow(InvalidKeyException::class, 'MAC key must be 32 bytes.')
        ->and(fn () => $macService->verifyWithBinaryKey('message', 'invalid', 'short'))
        ->toThrow(InvalidKeyException::class, 'MAC key must be 32 bytes.');

    try {
        $macService->generate('message', 'short');
        test()->fail('Malformed encoded MAC key was accepted.');
    } catch (InvalidKeyException $exception) {
        expect($exception->getCode())->toBe(0)
            ->and($exception->getPrevious())->toBeInstanceOf(InvalidKeyException::class);
    }
});
