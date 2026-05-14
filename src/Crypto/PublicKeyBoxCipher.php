<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\CipherInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class PublicKeyBoxCipher implements CipherInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $key = $this->normalizeKeyMaterial($key, 'Key must include sender_public and recipient_private entries.');

        try {
            [$senderPublic, $recipientPrivate] = $this->resolveBoxKeyPair(
                $key,
                (bool) ($context['key_is_binary'] ?? false),
                'sender_public',
                'recipient_private',
            );
        } catch (InvalidKeyException $e) {
            throw new DecryptionException('Public key-box decryption key material is invalid.', 0, $e);
        }

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        $plaintext = sodium_crypto_box_open(
            Base64Url::decode($parsedPayload->parts[1]),
            Base64Url::decode($parsedPayload->parts[0]),
            sodium_crypto_box_keypair_from_secretkey_and_publickey($recipientPrivate, $senderPublic),
        );

        if (!is_string($plaintext)) {
            throw new DecryptionException('Public key-box decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $key = $this->normalizeKeyMaterial($key, 'Key must include recipient_public and sender_private entries.');

        try {
            [$recipientPublic, $senderPrivate] = $this->resolveBoxKeyPair(
                $key,
                (bool) ($context['key_is_binary'] ?? false),
                'recipient_public',
                'sender_private',
            );
        } catch (InvalidKeyException $e) {
            throw new EncryptionException('Public key-box encryption key material is invalid.', 0, $e);
        }
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        $ciphertext = sodium_crypto_box(
            $plaintext,
            $nonce,
            sodium_crypto_box_keypair_from_secretkey_and_publickey($senderPrivate, $recipientPublic),
        );

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function normalizeKeyMaterial(mixed $key, string $invalidMessage): array
    {
        if (!is_array($key)) {
            throw new InvalidKeyException($invalidMessage);
        }

        $normalized = [];
        foreach ($key as $entryKey => $entryValue) {
            if (!is_string($entryKey)) {
                throw new InvalidKeyException($invalidMessage);
            }

            $normalized[$entryKey] = $entryValue;
        }

        return $normalized;
    }

    /**
     * @param array<string, mixed> $key
     * @return array{0: string, 1: string}
     */
    private function resolveBoxKeyPair(array $key, bool $keyIsBinary, string $publicKeyField, string $secretKeyField): array
    {
        return [
            BinaryKey::fixedLength($key[$publicKeyField] ?? null, $keyIsBinary, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, $publicKeyField),
            BinaryKey::fixedLength($key[$secretKeyField] ?? null, $keyIsBinary, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, $secretKeyField),
        ];
    }
}
