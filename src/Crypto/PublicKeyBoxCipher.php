<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\CipherInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class PublicKeyBoxCipher implements CipherInterface
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

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }
        [, $parts] = $parsedPayload;

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

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
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
