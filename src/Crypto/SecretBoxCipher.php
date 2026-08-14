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

    public function decrypt(string $ciphertext, #[\SensitiveParameter] string $key): string
    {
        return $this->decryptWithBinaryKey($ciphertext, $this->decodeKey($key, 'Decryption'));
    }

    public function decryptWithBinaryKey(string $ciphertext, #[\SensitiveParameter] string $key): string
    {
        $this->assertBinaryKey($key, 'Decryption');
        [$encodedNonce, $encodedCipher] = $this->splitPayload($ciphertext);

        try {
            $nonce = Base64Url::decode($encodedNonce);
            $encrypted = Base64Url::decode($encodedCipher);
        } catch (\Throwable $exception) {
            throw new DecryptionException('Invalid secret-box payload encoding.', 0, $exception);
        }
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new DecryptionException('Invalid secret-box payload nonce length.');
        }

        $plaintext = sodium_crypto_secretbox_open(
            $encrypted,
            $nonce,
            $key,
        );

        if (!is_string($plaintext)) {
            throw new DecryptionException('Secret-box decryption failed.');
        }

        return $plaintext;
    }

    public function encrypt(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
    ): string {
        return $this->encryptWithBinaryKey($plaintext, $this->decodeKey($key, 'Encryption'));
    }

    public function encryptWithBinaryKey(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
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
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

        return VersionedPayload::encodePrimitive(
            EncryptedPayloadVersion::V2->value,
            self::ALGORITHM_ID,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    private function assertBinaryKey(#[\SensitiveParameter] string $key, string $operation): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException(sprintf('%s key must be 32 bytes.', $operation));
        }
    }

    private function decodeKey(#[\SensitiveParameter] string $key, string $operation): string
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
        $payload = VersionedPayload::parsePrimitive($ciphertext, EncryptedPayloadVersion::V2->value);
        if ($payload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        if ($payload['algorithm'] !== self::ALGORITHM_ID) {
            throw new DecryptionException('Unsupported payload algorithm.');
        }

        return [$payload['nonce'], $payload['ciphertext']];
    }
}
