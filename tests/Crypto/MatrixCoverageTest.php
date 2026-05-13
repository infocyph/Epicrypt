<?php

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;
use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('roundtrips AEAD encryption for each supported algorithm', function () {
    $generator = new KeyMaterialGenerator;

    foreach (AeadAlgorithm::cases() as $algorithm) {
        if (!$algorithm->isAvailable()) {
            continue;
        }

        $key = $generator->forAead($algorithm);
        $cipher = new AeadCipher($algorithm);
        $ciphertext = $cipher->encrypt('aead-matrix-payload', $key, ['aad' => 'matrix']);
        $plaintext = $cipher->decrypt($ciphertext, $key, ['aad' => 'matrix']);

        expect($plaintext)->toBe('aead-matrix-payload');
    }
});

it('roundtrips sealed box encryption', function () {
    $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: false);
    $recipientKeypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($recipient['private'], $recipient['public']);

    $cipher = new SealedBoxCipher;
    $ciphertext = $cipher->encrypt('sealed-box payload', $recipient['public'], ['key_is_binary' => true]);
    $plaintext = $cipher->decrypt($ciphertext, $recipientKeypair, ['key_is_binary' => true]);

    expect($plaintext)->toBe('sealed-box payload');
});

it('roundtrips public key box encryption', function () {
    $sender = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: true);

    $cipher = new PublicKeyBoxCipher;
    $ciphertext = $cipher->encrypt('public-box payload', [
        'recipient_public' => $recipient['public'],
        'sender_private' => $sender['private'],
    ]);
    $plaintext = $cipher->decrypt($ciphertext, [
        'sender_public' => $sender['public'],
        'recipient_private' => $recipient['private'],
    ]);

    expect($plaintext)->toBe('public-box payload');
});

it('rejects wrong and invalid keys for secret box payloads', function () {
    $generator = new KeyMaterialGenerator;
    $correctKey = $generator->forSecretBox();
    $wrongKey = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;
    $ciphertext = $cipher->encrypt('secret-box payload', $correctKey);

    expect(fn() => $cipher->decrypt($ciphertext, $wrongKey))
        ->toThrow(DecryptionException::class);

    expect(fn() => $cipher->encrypt('secret-box payload', 'short'))
        ->toThrow(InvalidKeyException::class);
});

it('rejects tampered nonce, tampered ciphertext and invalid base64url', function () {
    $generator = new KeyMaterialGenerator;
    $key = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;
    $ciphertext = $cipher->encrypt('secret-box payload', $key);
    $parts = explode('.', $ciphertext);

    $tamperedNonce = $parts;
    $tamperedNonce[3] = 'not_base64url***';
    expect(fn() => $cipher->decrypt(implode('.', $tamperedNonce), $key))
        ->toThrow(ConfigurationException::class);

    $tamperedCiphertext = $parts;
    $tamperedCiphertext[4] = 'not_base64url***';
    expect(fn() => $cipher->decrypt(implode('.', $tamperedCiphertext), $key))
        ->toThrow(ConfigurationException::class);
});

it('supports secret-box key usage in binary and base64url modes', function () {
    $generator = new KeyMaterialGenerator;
    $binaryKey = $generator->forSecretBox(asBase64Url: false);
    $base64Key = $generator->forSecretBox();

    $cipher = new SecretBoxCipher;

    $binaryCiphertext = $cipher->encrypt('binary-key-payload', $binaryKey, ['key_is_binary' => true]);
    $base64Ciphertext = $cipher->encrypt('base64-key-payload', $base64Key);

    expect($cipher->decrypt($binaryCiphertext, $binaryKey, ['key_is_binary' => true]))->toBe('binary-key-payload');
    expect($cipher->decrypt($base64Ciphertext, $base64Key))->toBe('base64-key-payload');
});
