<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class PublicKeyBoxCipher
{
    public function decrypt(
        string $ciphertext,
        string $senderPublicKey,
        #[\SensitiveParameter]
        string $recipientPrivateKey,
    ): string {
        try {
            return $this->decryptWithBinaryKeys(
                $ciphertext,
                Base64Url::decode($senderPublicKey),
                Base64Url::decode($recipientPrivateKey),
            );
        } catch (DecryptionException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new DecryptionException('Public key-box decryption key material is invalid.', 0, $exception);
        }
    }

    public function decryptWithBinaryKeys(
        string $ciphertext,
        string $senderPublicKey,
        #[\SensitiveParameter]
        string $recipientPrivateKey,
    ): string {
        try {
            [$senderPublic, $recipientPrivate] = $this->resolveBoxKeyPair(
                $senderPublicKey,
                $recipientPrivateKey,
            );
        } catch (InvalidKeyException $e) {
            throw new DecryptionException('Public key-box decryption key material is invalid.', 0, $e);
        }

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V2->value, 2);
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

    public function encrypt(
        string $plaintext,
        string $recipientPublicKey,
        #[\SensitiveParameter]
        string $senderPrivateKey,
    ): string {
        try {
            return $this->encryptWithBinaryKeys(
                $plaintext,
                Base64Url::decode($recipientPublicKey),
                Base64Url::decode($senderPrivateKey),
            );
        } catch (EncryptionException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new EncryptionException('Public key-box encryption key material is invalid.', 0, $exception);
        }
    }

    public function encryptWithBinaryKeys(
        string $plaintext,
        string $recipientPublicKey,
        #[\SensitiveParameter]
        string $senderPrivateKey,
    ): string {
        try {
            [$recipientPublic, $senderPrivate] = $this->resolveBoxKeyPair(
                $recipientPublicKey,
                $senderPrivateKey,
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
            EncryptedPayloadVersion::V2->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    /** @return array{string, string} */
    private function resolveBoxKeyPair(string $publicKey, string $secretKey): array
    {
        return [
            BinaryKey::fixedLength($publicKey, true, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Public key'),
            BinaryKey::fixedLength($secretKey, true, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'Private key'),
        ];
    }
}
