<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class SealedBoxCipher implements EncryptorInterface, DecryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Recipient keypair must be a non-empty string.');
        }

        $keypair = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($keypair) !== SODIUM_CRYPTO_BOX_KEYPAIRBYTES) {
            throw new InvalidKeyException('Recipient keypair has invalid length.');
        }

        $plaintext = sodium_crypto_box_seal_open(Base64Url::decode($ciphertext), $keypair);
        if (! is_string($plaintext)) {
            throw new DecryptionException('Sealed-box decryption failed.');
        }

        return $plaintext;
    }
    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Recipient public key must be a non-empty string.');
        }

        $publicKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyException('Recipient public key has invalid length.');
        }

        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);
        if (! is_string($ciphertext)) {
            throw new EncryptionException('Sealed-box encryption failed.');
        }

        return Base64Url::encode($ciphertext);
    }
}
