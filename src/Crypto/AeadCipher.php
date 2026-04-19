<?php

declare(strict_types=1);

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
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

final readonly class AeadCipher implements CipherInterface
{
    public function __construct(private AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF, private SecurityProfile $profile = SecurityProfile::MODERN) {}

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN): self
    {
        return new self($profile->defaultAeadAlgorithm(), $profile);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $this->assertAlgorithmAvailability();

        $decodedKey = $this->decodeKey($key, $this->algorithm->keyLength(), $this->boolFromContext($context, 'key_is_binary'), 'Decryption');

        $parsedPayload = VersionedPayload::parse($ciphertext, EncryptedPayloadVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }
        [, $parts] = $parsedPayload;

        $nonce = Base64Url::decode($parts[0]);
        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $aad = $this->aadFromContext($context);
        $plaintext = $this->decryptRaw(Base64Url::decode($parts[1]), $aad, $nonce, $decodedKey);

        if (!is_string($plaintext)) {
            throw new DecryptionException('AEAD decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        if (!$this->profile->allowsWrites()) {
            throw new EncryptionException('AEAD encryption is disabled for the legacy-decrypt-only profile.');
        }

        $this->assertAlgorithmAvailability();

        $decodedKey = $this->decodeKey($key, $this->algorithm->keyLength(), $this->boolFromContext($context, 'key_is_binary'), 'Encryption');

        if (array_key_exists('nonce', $context)) {
            $nonce = $context['nonce'];
            if (!is_string($nonce) || $nonce === '') {
                throw new InvalidNonceException('Nonce must be a non-empty string.');
            }

            if (!$this->boolFromContext($context, 'nonce_is_binary')) {
                $nonce = Base64Url::decode($nonce);
            }
        } else {
            $nonce = random_bytes($this->algorithm->nonceLength());
        }

        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $aad = $this->aadFromContext($context);
        $ciphertext = $this->encryptRaw($plaintext, $aad, $nonce, $decodedKey);

        return VersionedPayload::encode(
            EncryptedPayloadVersion::V1->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    /**
     * @param array<string, mixed> $context
     */
    private function aadFromContext(array $context): string
    {
        $aad = $context['aad'] ?? '';
        if (!is_string($aad)) {
            throw new CryptoException('AAD must be a string.');
        }

        return $aad;
    }

    private function assertAlgorithmAvailability(): void
    {
        if (!$this->algorithm->isAvailable()) {
            throw new CryptoException('AES-256-GCM hardware support is not available.');
        }
    }

    /**
     * @param array<string, mixed> $context
     */
    private function boolFromContext(array $context, string $key): bool
    {
        $value = $context[$key] ?? false;
        if (!is_bool($value)) {
            throw new CryptoException(sprintf('Context value "%s" must be boolean.', $key));
        }

        return $value;
    }

    private function decodeKey(mixed $key, int $expectedLength, bool $isBinary, string $operation): string
    {
        if (!is_string($key) || $key === '') {
            throw new InvalidKeyException(sprintf('%s key must be a non-empty string.', $operation));
        }

        $decoded = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength));
        }

        return $decoded;
    }

    private function decryptRaw(string $ciphertext, string $aad, string $nonce, string $key): string|false
    {
        return match ($this->algorithm) {
            AeadAlgorithm::AES_256_GCM => sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305 => sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305_IETF => sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key),
            AeadAlgorithm::XCHACHA20_POLY1305_IETF => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key),
        };
    }

    private function encryptRaw(string $plaintext, string $aad, string $nonce, string $key): string
    {
        return match ($this->algorithm) {
            AeadAlgorithm::AES_256_GCM => sodium_crypto_aead_aes256gcm_encrypt($plaintext, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305 => sodium_crypto_aead_chacha20poly1305_encrypt($plaintext, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305_IETF => sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key),
            AeadAlgorithm::XCHACHA20_POLY1305_IETF => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key),
        };
    }
}
