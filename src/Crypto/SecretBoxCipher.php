<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\CipherInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class SecretBoxCipher implements CipherInterface
{
    public const string ALGORITHM_ID = 'secretbox';

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $decodedKey = $this->decodeKey($key, $context, 'Decryption');
        [$encodedNonce, $encodedCipher] = $this->splitPayload($ciphertext);

        $plaintext = sodium_crypto_secretbox_open(
            Base64Url::decode($encodedCipher),
            Base64Url::decode($encodedNonce),
            $decodedKey,
        );

        if (!is_string($plaintext)) {
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
        $keyId = $this->keyIdFromContext($context);

        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $decodedKey);

        return VersionedPayload::encodeCompact(
            EncryptedPayloadVersion::V1->value,
            self::ALGORITHM_ID,
            $keyId,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    public function parseKeyId(string $ciphertext): ?string
    {
        $compactPayload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V1->value);
        if ($compactPayload === null || $compactPayload->algorithm !== self::ALGORITHM_ID) {
            return null;
        }

        return $compactPayload->keyId;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function decodeKey(mixed $key, array $context, string $operation): string
    {
        try {
            return BinaryKey::fixedLength(
                $key,
                (bool) ($context['key_is_binary'] ?? false),
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                sprintf('%s key', $operation),
            );
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException(sprintf('%s key must be 32 bytes.', $operation), 0, $e);
        }
    }

    /**
     * @param array<string, mixed> $context
     */
    private function keyIdFromContext(array $context): ?string
    {
        $keyId = $context['key_id'] ?? null;
        if ($keyId === null) {
            return null;
        }

        if (!is_string($keyId) || $keyId === '') {
            throw new InvalidKeyException('Context key_id must be a non-empty string when provided.');
        }

        return $keyId;
    }

    /**
     * @return array{string, string}
     */
    private function splitPayload(string $ciphertext): array
    {
        $compactPayload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V1->value);
        if ($compactPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        if ($compactPayload->algorithm !== self::ALGORITHM_ID) {
            throw new DecryptionException('Unsupported payload algorithm.');
        }

        return [$compactPayload->nonce, $compactPayload->ciphertext];
    }
}
