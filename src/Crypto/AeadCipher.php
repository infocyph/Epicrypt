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
    private bool $available;

    public function __construct(private AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF)
    {
        $this->available = $algorithm->isAvailable();
    }

    public function decrypt(
        string $ciphertext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
    ): string {
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

        try {
            $nonce = Base64Url::decode($encodedNonce);
            $encrypted = Base64Url::decode($encodedCiphertext);
        } catch (\Throwable $exception) {
            throw new DecryptionException('Invalid AEAD payload encoding.', 0, $exception);
        }
        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new DecryptionException('Invalid AEAD payload nonce length.');
        }

        $plaintext = $this->decryptRaw($encrypted, $aad, $nonce, $key);

        if (!is_string($plaintext)) {
            throw new DecryptionException('AEAD decryption failed.');
        }

        return $plaintext;
    }

    public function encrypt(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
    ): string {
        return $this->encryptWithBinaryKey(
            $plaintext,
            $this->decodeKey($key, $this->algorithm->keyLength(), 'Encryption'),
            $aad,
        );
    }

    public function encryptWithBinaryKey(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $aad = '',
        ?string $nonce = null,
    ): string {
        $this->assertAlgorithmAvailability();
        $this->assertBinaryKey($key, $this->algorithm->keyLength(), 'Encryption');
        $nonce ??= random_bytes($this->algorithm->nonceLength());

        if (strlen($nonce) !== $this->algorithm->nonceLength()) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $this->algorithm->nonceLength()));
        }

        $ciphertext = $this->encryptRaw($plaintext, $aad, $nonce, $key);

        return VersionedPayload::encodePrimitive(
            EncryptedPayloadVersion::V2->value,
            $this->algorithm->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    private function assertAlgorithmAvailability(): void
    {
        if (!$this->available) {
            throw new CryptoException(sprintf('%s is not available in the linked libsodium runtime.', $this->algorithm->value));
        }
    }

    private function assertBinaryKey(#[\SensitiveParameter] string $key, int $expectedLength, string $operation): void
    {
        if (strlen($key) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength));
        }
    }

    private function decodeKey(#[\SensitiveParameter] string $key, int $expectedLength, string $operation): string
    {
        try {
            return BinaryKey::fixedLength($key, false, $expectedLength, sprintf('%s key', $operation));
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength), 0, $e);
        }
    }

    private function decryptRaw(
        string $ciphertext,
        string $aad,
        string $nonce,
        #[\SensitiveParameter]
        string $key,
    ): string|false {
        return $this->runRawOperation($ciphertext, $aad, $nonce, $key, true);
    }

    private function encryptRaw(
        #[\SensitiveParameter]
        string $plaintext,
        string $aad,
        string $nonce,
        #[\SensitiveParameter]
        string $key,
    ): string {
        $result = $this->runRawOperation($plaintext, $aad, $nonce, $key, false);
        if (!is_string($result)) {
            throw new EncryptionException('Encryption failed.');
        }

        return $result;
    }

    private function runOptionalSodiumAead(
        string $prefix,
        #[\SensitiveParameter]
        string $input,
        string $aad,
        string $nonce,
        #[\SensitiveParameter]
        string $key,
        bool $decrypt,
    ): string|false {
        $function = $prefix . ($decrypt ? '_decrypt' : '_encrypt');
        if (!is_callable($function)) {
            throw new CryptoException(sprintf('%s is unavailable.', $this->algorithm->value));
        }
        $result = $function($input, $aad, $nonce, $key);

        return is_string($result) ? $result : false;
    }

    private function runRawOperation(
        #[\SensitiveParameter]
        string $input,
        string $aad,
        string $nonce,
        #[\SensitiveParameter]
        string $key,
        bool $decrypt,
    ): string|false {
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
            AeadAlgorithm::AEGIS_128L => $this->runOptionalSodiumAead('sodium_crypto_aead_aegis128l', $input, $aad, $nonce, $key, $decrypt),
            AeadAlgorithm::AEGIS_256 => $this->runOptionalSodiumAead('sodium_crypto_aead_aegis256', $input, $aad, $nonce, $key, $decrypt),
        };
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

        if ($payload['algorithm'] !== $this->algorithm->value) {
            throw new DecryptionException(sprintf('Unsupported payload algorithm "%s".', $payload['algorithm']));
        }

        return [$payload['nonce'], $payload['ciphertext']];
    }
}
