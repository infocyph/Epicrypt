<?php

namespace Infocyph\Epicrypt\Sodium;

use Exception;
use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final class SodiumAead
{
    use Base64Codec;

    private array $keyLength = [
        'aes-256-gcm' => 12,
        'chacha20-poly1305' => 8,
        'chacha20-poly1305-ietf' => 12,
        'xchacha20-poly1305-ietf' => 24,
    ];

    private array $algorithms = [
        'aes-256-gcm' => 'aes256gcm',
        'chacha20-poly1305' => 'chacha20poly1305',
        'chacha20-poly1305-ietf' => 'chacha20poly1305_ietf',
        'xchacha20-poly1305-ietf' => 'xchacha20poly1305_ietf',
    ];

    /**
     * Provide required data for operation
     *
     * @param  string  $algorithm  Algorithm
     * @param  bool  $isMessageBinary  Message is binary?
     * @param  bool  $isSecretBinary  Secrets (nonce, encryption key) are binary?
     */
    public function __construct(
        private readonly string $algorithm = 'xchacha20-poly1305-ietf',
        private readonly bool $isMessageBinary = false,
        private readonly bool $isSecretBinary = false,
    ) {}

    /**
     * Encrypts the given message using the specified key and nonce.
     *
     * @param  string  $message  The message to be encrypted.
     * @param  string  $key  The key used for encryption.
     * @param  string  $nonce  The nonce used for encryption (must be only used once, per message).
     * @param  string  $additionalData  Additional, authenticated data
     * @return string The encrypted message.
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function encrypt(
        #[\SensitiveParameter] string $message,
        #[\SensitiveParameter] string $key,
        string $nonce,
        string $additionalData,
    ): string {
        $this->checkSupport();

        if (! $this->isSecretBinary) {
            $key = $this->base642binSodium($key);
            $nonce = $this->base642binSodium($nonce);
        }

        $encrypted = call_user_func_array(
            'sodium_crypto_aead_'.$this->algorithms[$this->algorithm].'_encrypt',
            [$message, $additionalData, $nonce, $key],
        );

        return $this->isMessageBinary ? $encrypted : $this->bin2base64($encrypted);
    }

    /**
     * Decrypts the given encrypted data using the specified key and nonce.
     *
     * @param  string  $encrypted  The encrypted data to be decrypted.
     * @param  string  $key  The key used for decryption.
     * @param  string  $nonce  The nonce used for decryption.
     * @param  string  $additionalData  Additional, authenticated data
     * @return string|false The decrypted data.
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function decrypt(
        string $encrypted,
        #[\SensitiveParameter] string $key,
        string $nonce,
        string $additionalData,
    ): string|false {
        $this->checkSupport();

        if (! $this->isSecretBinary) {
            $key = $this->base642binSodium($key);
            $nonce = $this->base642binSodium($nonce);
        }

        if (! $this->isMessageBinary) {
            $encrypted = $this->base642bin($encrypted);
        }

        return call_user_func_array(
            'sodium_crypto_aead_'.$this->algorithms[$this->algorithm].'_decrypt',
            [$encrypted, $additionalData, $nonce, $key],
        );
    }

    /**
     * Get nonce, usable once per message
     *
     * @return string The generated nonce.
     *
     * @throws Exception
     */
    public function generateNonce(): string
    {
        $nonce = random_bytes($this->keyLength[$this->algorithm]);

        return $this->isSecretBinary ? $nonce : $this->bin2base64Sodium($nonce);
    }

    /**
     * Retrieves the global encryption key.
     *
     * @return string The encryption key.
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function generateEncryptionKey(): string
    {
        $this->checkSupport();
        $encryptionKey = call_user_func('sodium_crypto_aead_'.$this->algorithms[$this->algorithm].'_keygen');

        return $this->isSecretBinary ? $encryptionKey : $this->bin2base64Sodium($encryptionKey);
    }

    /**
     * Checks if the specified algorithm is supported and if hardware support is available for AES-256-GCM.
     *
     * @throws SodiumCryptoException
     */
    private function checkSupport(): void
    {
        if (! isset($this->algorithms[$this->algorithm])) {
            throw new SodiumCryptoException(
                'Invalid algorithm! Available: '.implode(', ', array_keys($this->algorithms)),
            );
        }

        if ($this->algorithm === 'aes-256-gcm' && ! sodium_crypto_aead_aes256gcm_is_available()) {
            throw new SodiumCryptoException('Hardware support not available for AES-256-GCM!');
        }
    }
}
