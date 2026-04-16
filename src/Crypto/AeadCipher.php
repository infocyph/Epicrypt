<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\CipherInterface;
use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final readonly class AeadCipher implements CipherInterface
{
    public function __construct(private AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF) {}

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $this->assertAlgorithmAvailability();

        $decodedKey = $this->decodeKey($key, $this->algorithm->keyLength(), (bool) ($context['key_is_binary'] ?? false), 'Decryption');

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }
        [, $parts] = $parsedPayload;

        $nonce = Base64Url::decode($parts[0]);
        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $aad = (string) ($context['aad'] ?? '');
        $plaintext = call_user_func(
            'sodium_crypto_aead_' . $this->algorithm->sodiumSuffix() . '_decrypt',
            Base64Url::decode($parts[1]),
            $aad,
            $nonce,
            $decodedKey,
        );

        if (! is_string($plaintext)) {
            throw new DecryptionException('AEAD decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $this->assertAlgorithmAvailability();

        $decodedKey = $this->decodeKey($key, $this->algorithm->keyLength(), (bool) ($context['key_is_binary'] ?? false), 'Encryption');

        if (array_key_exists('nonce', $context)) {
            $nonce = $context['nonce'];
            if (! is_string($nonce) || $nonce === '') {
                throw new InvalidNonceException('Nonce must be a non-empty string.');
            }

            if (! (bool) ($context['nonce_is_binary'] ?? false)) {
                $nonce = Base64Url::decode($nonce);
            }
        } else {
            $nonce = random_bytes($this->algorithm->nonceLength());
        }

        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $aad = (string) ($context['aad'] ?? '');

        $ciphertext = call_user_func(
            'sodium_crypto_aead_' . $this->algorithm->sodiumSuffix() . '_encrypt',
            $plaintext,
            $aad,
            $nonce,
            $decodedKey,
        );

        if (! is_string($ciphertext)) {
            throw new EncryptionException('AEAD encryption failed.');
        }

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    private function assertAlgorithmAvailability(): void
    {
        if (! $this->algorithm->isAvailable()) {
            throw new CryptoException('AES-256-GCM hardware support is not available.');
        }
    }

    private function decodeKey(mixed $key, int $expectedLength, bool $isBinary, string $operation): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException(sprintf('%s key must be a non-empty string.', $operation));
        }

        $decoded = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength));
        }

        return $decoded;
    }
}
