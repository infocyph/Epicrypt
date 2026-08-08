<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final readonly class AeadCipher
{
    public function __construct(private AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF) {}

    public function decrypt(string $ciphertext, string $key, string $aad = ''): string
    {
        return $this->decryptWithBinaryKey(
            $ciphertext,
            $this->decodeKey($key, $this->algorithm->keyLength(), 'Decryption'),
            $aad,
        );
    }

    public function decryptWithBinaryKey(
        string $ciphertext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
    ): string {
        $this->assertAlgorithmAvailability();
        $this->assertBinaryKey($key, $this->algorithm->keyLength(), 'Decryption');
        [$encodedNonce, $encodedCiphertext] = $this->splitPayload($ciphertext);

        $nonce = Base64Url::decode($encodedNonce);
        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $plaintext = $this->decryptRaw(Base64Url::decode($encodedCiphertext), $aad, $nonce, $key);

        if (!is_string($plaintext)) {
            throw new DecryptionException('AEAD decryption failed.');
        }

        return $plaintext;
    }

    public function encrypt(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
        ?string $keyId = null,
    ): string {
        return $this->encryptWithBinaryKey(
            $plaintext,
            $this->decodeKey($key, $this->algorithm->keyLength(), 'Encryption'),
            $aad,
            $keyId,
        );
    }

    public function encryptWithBinaryKey(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
        ?string $keyId = null,
        ?string $nonce = null,
    ): string {
        $this->assertAlgorithmAvailability();
        $this->assertBinaryKey($key, $this->algorithm->keyLength(), 'Encryption');
        $nonce ??= random_bytes($this->algorithm->nonceLength());

        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $ciphertext = $this->encryptRaw($plaintext, $aad, $nonce, $key);

        return VersionedPayload::encodeCompact(
            EncryptedPayloadVersion::V2->value,
            $this->algorithm->value,
            $keyId,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    private function assertAlgorithmAvailability(): void
    {
        if (!$this->algorithm->isAvailable()) {
            throw new CryptoException('AES-256-GCM hardware support is not available.');
        }
    }

    private function assertBinaryKey(string $key, int $expectedLength, string $operation): void
    {
        if (strlen($key) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength));
        }
    }

    private function decodeKey(string $key, int $expectedLength, string $operation): string
    {
        try {
            return BinaryKey::fixedLength($key, false, $expectedLength, sprintf('%s key', $operation));
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength), 0, $e);
        }
    }

    private function decryptRaw(string $ciphertext, string $aad, string $nonce, string $key): string|false
    {
        return $this->runRawOperation($ciphertext, $aad, $nonce, $key, true);
    }

    private function encryptRaw(string $plaintext, string $aad, string $nonce, string $key): string
    {
        $result = $this->runRawOperation($plaintext, $aad, $nonce, $key, false);
        if (!is_string($result)) {
            throw new EncryptionException('Encryption failed.');
        }

        return $result;
    }

    private function runRawOperation(string $input, string $aad, string $nonce, string $key, bool $decrypt): string|false
    {
        return match ($this->algorithm) {
            AeadAlgorithm::AES_256_GCM => $decrypt
                ? sodium_crypto_aead_aes256gcm_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_aes256gcm_encrypt($input, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305 => $decrypt
                ? sodium_crypto_aead_chacha20poly1305_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_chacha20poly1305_encrypt($input, $aad, $nonce, $key),
            AeadAlgorithm::CHACHA20_POLY1305_IETF => $decrypt
                ? sodium_crypto_aead_chacha20poly1305_ietf_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_chacha20poly1305_ietf_encrypt($input, $aad, $nonce, $key),
            AeadAlgorithm::XCHACHA20_POLY1305_IETF => $decrypt
                ? sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($input, $aad, $nonce, $key),
        };
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

        if ($compactPayload->algorithm !== $this->algorithm->value) {
            throw new DecryptionException(sprintf('Unsupported payload algorithm "%s".', $compactPayload->algorithm));
        }

        return [$compactPayload->nonce, $compactPayload->ciphertext];
    }
}
