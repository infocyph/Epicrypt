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

final class SealedBoxCipher
{
    public function decrypt(string $ciphertext, #[\SensitiveParameter] string $keypair): string
    {
        try {
            return $this->decryptWithBinaryKey($ciphertext, Base64Url::decode($keypair));
        } catch (DecryptionException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new DecryptionException('Recipient keypair must be valid.', 0, $exception);
        }
    }

    public function decryptWithBinaryKey(string $ciphertext, #[\SensitiveParameter] string $keypair): string
    {
        try {
            $keypair = BinaryKey::fixedLength($keypair, true, SODIUM_CRYPTO_BOX_KEYPAIRBYTES, 'Recipient keypair');
        } catch (InvalidKeyException $e) {
            throw new DecryptionException('Recipient keypair must be valid.', 0, $e);
        }

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V2->value, 1);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        $plaintext = sodium_crypto_box_seal_open(Base64Url::decode($parsedPayload->parts[0]), $keypair);
        if (!is_string($plaintext)) {
            throw new DecryptionException('Sealed-box decryption failed.');
        }

        return $plaintext;
    }

    public function encrypt(string $plaintext, string $publicKey): string
    {
        try {
            return $this->encryptWithBinaryKey($plaintext, Base64Url::decode($publicKey));
        } catch (EncryptionException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new EncryptionException('Recipient public key must be valid.', 0, $exception);
        }
    }

    public function encryptWithBinaryKey(string $plaintext, string $publicKey): string
    {
        try {
            $publicKey = BinaryKey::fixedLength($publicKey, true, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Recipient public key');
        } catch (InvalidKeyException $e) {
            throw new EncryptionException('Recipient public key must be valid.', 0, $e);
        }

        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V2->value,
            Base64Url::encode($ciphertext),
        );
    }
}
