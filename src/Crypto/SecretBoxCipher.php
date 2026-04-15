<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class SecretBoxCipher implements EncryptorInterface, DecryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $decodedKey = $this->decodeKey($key, $context, 'Decryption');

        $parts = explode('.', $ciphertext, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        $plaintext = sodium_crypto_secretbox_open(
            Base64Url::decode($parts[1]),
            Base64Url::decode($parts[0]),
            $decodedKey,
        );

        if (! is_string($plaintext)) {
            throw new DecryptionException('Secret-box decryption failed.');
        }

        return $plaintext;
    }
    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $decodedKey = $this->decodeKey($key, $context, 'Encryption');
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $decodedKey);
        if (! is_string($ciphertext)) {
            throw new EncryptionException('Secret-box encryption failed.');
        }

        return Base64Url::encode($nonce) . '.' . Base64Url::encode($ciphertext);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function decodeKey(mixed $key, array $context, string $operation): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException(sprintf('%s key must be a non-empty string.', $operation));
        }

        $decodedKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException(sprintf('%s key must be 32 bytes.', $operation));
        }

        return $decodedKey;
    }
}
