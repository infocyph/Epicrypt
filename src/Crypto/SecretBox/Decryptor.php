<?php

namespace Infocyph\Epicrypt\Crypto\SecretBox;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Decryptor implements DecryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Decryption key must be a non-empty string.');
        }

        $decodedKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException('Decryption key must be 32 bytes.');
        }

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
}
