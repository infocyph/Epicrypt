<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\CipherInterface;
use Infocyph\Epicrypt\Crypto\Support\KeyDecoder;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class SealedBoxCipher implements CipherInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $keypair = KeyDecoder::decode(
            $key,
            (bool) ($context['key_is_binary'] ?? false),
            SODIUM_CRYPTO_BOX_KEYPAIRBYTES,
            'Recipient keypair',
        );

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 1);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }
        [, $parts] = $parsedPayload;

        $plaintext = sodium_crypto_box_seal_open(Base64Url::decode($parts[0]), $keypair);
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
        $publicKey = KeyDecoder::decode(
            $key,
            (bool) ($context['key_is_binary'] ?? false),
            SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
            'Recipient public key',
        );

        $ciphertext = sodium_crypto_box_seal($plaintext, $publicKey);

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($ciphertext),
        );
    }
}
