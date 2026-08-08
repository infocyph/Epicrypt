<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final class SecretBoxCipher
{
    public const string ALGORITHM_ID = 'secretbox';

    public function decrypt(string $ciphertext, string $key): string
    {
        return $this->decryptWithBinaryKey($ciphertext, $this->decodeKey($key, 'Decryption'));
    }

    public function decryptWithBinaryKey(string $ciphertext, #[\SensitiveParameter] string $key): string
    {
        $this->assertBinaryKey($key, 'Decryption');
        [$encodedNonce, $encodedCipher] = $this->splitPayload($ciphertext);
        $nonce = Base64Url::decode($encodedNonce);
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', SODIUM_CRYPTO_SECRETBOX_NONCEBYTES));
        }

        $plaintext = sodium_crypto_secretbox_open(
            Base64Url::decode($encodedCipher),
            $nonce,
            $key,
        );

        if (!is_string($plaintext)) {
            throw new DecryptionException('Secret-box decryption failed.');
        }

        return $plaintext;
    }

    public function encrypt(string $plaintext, #[\SensitiveParameter] string $key, ?string $keyId = null): string
    {
        return $this->encryptWithBinaryKey($plaintext, $this->decodeKey($key, 'Encryption'), $keyId);
    }

    public function encryptWithBinaryKey(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ?string $keyId = null,
        ?string $nonce = null,
    ): string {
        $this->assertBinaryKey($key, 'Encryption');
        $nonce ??= random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new InvalidNonceException(sprintf(
                'Nonce must be %d bytes.',
                SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,
            ));
        }
        if ($keyId !== null && preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $keyId) !== 1) {
            throw new InvalidKeyException('Key id must be a Base64URL-safe identifier.');
        }

        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

        return VersionedPayload::encodeCompact(
            EncryptedPayloadVersion::V2->value,
            self::ALGORITHM_ID,
            $keyId,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    public function parseKeyId(string $ciphertext): ?string
    {
        $compactPayload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V2->value);
        if ($compactPayload === null || $compactPayload->algorithm !== self::ALGORITHM_ID) {
            return null;
        }

        return $compactPayload->keyId;
    }

    private function assertBinaryKey(string $key, string $operation): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException(sprintf('%s key must be 32 bytes.', $operation));
        }
    }

    private function decodeKey(string $key, string $operation): string
    {
        try {
            return BinaryKey::fixedLength(
                $key,
                false,
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                sprintf('%s key', $operation),
            );
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException(sprintf('%s key must be 32 bytes.', $operation), 0, $e);
        }
    }

    /**
     * @return array{string, string}
     */
    private function splitPayload(string $ciphertext): array
    {
        $compactPayload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V2->value);
        if ($compactPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        if ($compactPayload->algorithm !== self::ALGORITHM_ID) {
            throw new DecryptionException('Unsupported payload algorithm.');
        }

        return [$compactPayload->nonce, $compactPayload->ciphertext];
    }
}
