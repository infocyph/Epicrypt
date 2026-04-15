<?php

namespace Infocyph\Epicrypt\Crypto\PublicKeyBox;

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
        if (! is_array($key)) {
            throw new InvalidKeyException('Key must include sender_public and recipient_private entries.');
        }

        $senderPublic = $this->decodeKey($key['sender_public'] ?? null, 'sender_public', $context);
        $recipientPrivate = $this->decodeKey($key['recipient_private'] ?? null, 'recipient_private', $context);

        $parts = explode('.', $ciphertext, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        $plaintext = sodium_crypto_box_open(
            Base64Url::decode($parts[1]),
            Base64Url::decode($parts[0]),
            sodium_crypto_box_keypair_from_secretkey_and_publickey($recipientPrivate, $senderPublic),
        );

        if (! is_string($plaintext)) {
            throw new DecryptionException('Public key-box decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function decodeKey(mixed $value, string $name, array $context): string
    {
        if (! is_string($value) || $value === '') {
            throw new InvalidKeyException(sprintf('%s must be a non-empty string.', $name));
        }

        $decoded = (bool) ($context['key_is_binary'] ?? false) ? $value : Base64Url::decode($value);
        if (strlen($decoded) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES && strlen($decoded) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyException(sprintf('%s has invalid key length.', $name));
        }

        return $decoded;
    }
}
