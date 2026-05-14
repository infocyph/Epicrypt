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

final class SealedBoxCipher implements CipherInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        try {
            $keypair = BinaryKey::fixedLength($key, (bool) ($context['key_is_binary'] ?? false), SODIUM_CRYPTO_BOX_KEYPAIRBYTES, 'Recipient keypair');
        } catch (InvalidKeyException $e) {
            throw new DecryptionException('Recipient keypair must be valid.', 0, $e);
        }

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 1);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        $plaintext = sodium_crypto_box_seal_open(Base64Url::decode($parsedPayload->parts[0]), $keypair);
        if (!is_string($plaintext)) {
            throw new DecryptionException('Sealed-box decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        try {
            $publicKey = BinaryKey::fixedLength($key, (bool) ($context['key_is_binary'] ?? false), SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Recipient public key');
        } catch (InvalidKeyException $e) {
            throw new EncryptionException('Recipient public key must be valid.', 0, $e);
        }

        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($ciphertext),
        );
    }
}
