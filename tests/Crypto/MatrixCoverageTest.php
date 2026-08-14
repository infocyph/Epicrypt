<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;
use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Base64Url;

it('enforces the AEAD contract for each supported algorithm', function () {
    $generator = new KeyMaterialGenerator;
    $algorithms = array_values(array_filter(
        AeadAlgorithm::cases(),
        static fn(AeadAlgorithm $algorithm): bool => $algorithm->isAvailable(),
    ));

    foreach ($algorithms as $algorithm) {
        $key = $generator->forAead($algorithm);
        $binaryKey = $generator->forAead($algorithm, false);
        $cipher = new AeadCipher($algorithm);
        $ciphertext = $cipher->encrypt('aead-matrix-payload', $key, 'matrix');
        $parts = explode('.', $ciphertext);
        $corrupted = $parts;
        $rawCiphertext = Base64Url::decode($corrupted[3]);
        $rawCiphertext[0] = chr(ord($rawCiphertext[0]) ^ 1);
        $corrupted[3] = Base64Url::encode($rawCiphertext);
        $unsupported = $parts;
        $unsupported[1] = 'unsupported-aead';
        $otherAlgorithm = array_find(
            $algorithms,
            static fn(AeadAlgorithm $candidate): bool => $candidate !== $algorithm
                && $candidate->keyLength() === $algorithm->keyLength(),
        );

        expect($cipher->decrypt($ciphertext, $key, 'matrix'))->toBe('aead-matrix-payload')
            ->and(fn() => $cipher->encrypt('value', $generator->generate($algorithm->keyLength() - 1)))
            ->toThrow(InvalidKeyException::class)
            ->and(fn() => $cipher->encryptWithBinaryKey('value', $binaryKey, nonce: 'short'))
            ->toThrow(InvalidNonceException::class)
            ->and(fn() => $cipher->decrypt(implode('.', $corrupted), $key, 'matrix'))
            ->toThrow(DecryptionException::class)
            ->and(fn() => $cipher->decrypt(implode('.', $unsupported), $key, 'matrix'))
            ->toThrow(DecryptionException::class);

        if ($otherAlgorithm instanceof AeadAlgorithm) {
            expect(fn() => (new AeadCipher($otherAlgorithm))->decrypt($ciphertext, $key, 'matrix'))
                ->toThrow(DecryptionException::class);
        }
    }
});

it('roundtrips sealed box encryption', function () {
    $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: false);
    $recipientKeypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($recipient['private'], $recipient['public']);

    $cipher = new SealedBoxCipher;
    $ciphertext = $cipher->encryptWithBinaryKey('sealed-box payload', $recipient['public']);
    $plaintext = $cipher->decryptWithBinaryKey($ciphertext, $recipientKeypair);

    expect($plaintext)->toBe('sealed-box payload');
});

it('roundtrips public key box encryption', function () {
    $sender = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: true);

    $cipher = new PublicKeyBoxCipher;
    $ciphertext = $cipher->encrypt('public-box payload', $recipient['public'], $sender['private']);
    $plaintext = $cipher->decrypt($ciphertext, $sender['public'], $recipient['private']);

    expect($plaintext)->toBe('public-box payload');
});

it('rejects wrong and invalid keys for secret box payloads', function () {
    $generator = new KeyMaterialGenerator;
    $correctKey = $generator->forSecretBox();
    $wrongKey = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;
    $ciphertext = $cipher->encrypt('secret-box payload', $correctKey);

    expect(fn () => $cipher->decrypt($ciphertext, $wrongKey))
        ->toThrow(DecryptionException::class);

    expect(fn () => $cipher->encrypt('secret-box payload', 'short'))
        ->toThrow(InvalidKeyException::class);
});

it('rejects tampered nonce, tampered ciphertext and invalid base64url', function () {
    $generator = new KeyMaterialGenerator;
    $key = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;
    $ciphertext = $cipher->encrypt('secret-box payload', $key);
    $parts = explode('.', $ciphertext);

    $tamperedNonce = $parts;
    $tamperedNonce[2] = 'not_base64url***';
    expect(fn () => $cipher->decrypt(implode('.', $tamperedNonce), $key))
        ->toThrow(DecryptionException::class);

    $tamperedCiphertext = $parts;
    $tamperedCiphertext[3] = 'not_base64url***';
    expect(fn () => $cipher->decrypt(implode('.', $tamperedCiphertext), $key))
        ->toThrow(DecryptionException::class);
});

it('supports secret-box key usage in binary and base64url modes', function () {
    $generator = new KeyMaterialGenerator;
    $binaryKey = $generator->forSecretBox(asBase64Url: false);
    $base64Key = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;

    $binaryCiphertext = $cipher->encryptWithBinaryKey('binary-key-payload', $binaryKey);
    $base64Ciphertext = $cipher->encrypt('base64-key-payload', $base64Key);

    expect($cipher->decryptWithBinaryKey($binaryCiphertext, $binaryKey))->toBe('binary-key-payload');
    expect($cipher->decrypt($base64Ciphertext, $base64Key))->toBe('base64-key-payload');
});
