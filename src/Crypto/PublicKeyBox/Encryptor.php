<?php

namespace Infocyph\Epicrypt\Crypto\PublicKeyBox;

use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Encryptor implements EncryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        if (! is_array($key)) {
            throw new InvalidKeyException('Key must include recipient_public and sender_private entries.');
        }

        $recipientPublic = $this->decodeKey($key['recipient_public'] ?? null, 'recipient_public', $context);
        $senderPrivate = $this->decodeKey($key['sender_private'] ?? null, 'sender_private', $context);
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        $ciphertext = sodium_crypto_box(
            $plaintext,
            $nonce,
            sodium_crypto_box_keypair_from_secretkey_and_publickey($senderPrivate, $recipientPublic),
        );

        if (! is_string($ciphertext)) {
            throw new EncryptionException('Public key-box encryption failed.');
        }

        return Base64Url::encode($nonce) . '.' . Base64Url::encode($ciphertext);
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
