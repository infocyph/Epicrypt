<?php

namespace AbmmHasan\SafeGuard\Symmetric\Sodium;

use Exception;
use SodiumException;

class SodiumAead
{
    private array $availableAlgorithms = [
        'aes256gcm' => 12,
        'chacha20poly1305' => 8,
        'chacha20poly1305_ietf' => 12,
        'xchacha20poly1305_ietf' => 24
    ];

    private string $keygen;
    private string $encrypt;
    private string $decrypt;

    /**
     * Provide required data for aead operation
     *
     * @param string $additionalData Additional, authenticated data
     * @param string $algorithm Algorithm
     * @param bool $isBinary get result as binary?
     */
    public function __construct(
        private readonly string $additionalData,
        private readonly string $algorithm = 'xchacha20poly1305_ietf',
        private readonly bool $isBinary = true
    ) {
        $this->keygen = "sodium_crypto_aead_{$this->algorithm}_keygen";
        $this->encrypt = "sodium_crypto_aead_{$this->algorithm}_encrypt";
        $this->decrypt = "sodium_crypto_aead_{$this->algorithm}_decrypt";
    }

    /**
     * Encrypt data
     *
     * @param string $message The message to encrypt
     * @param string $key The key to encrypt with
     * @param string $nonce A number that must be only used once, per message
     * @return mixed
     * @throws SodiumException|Exception
     */
    public function encrypt(string $message, string $key, string $nonce): mixed
    {
        $this->checkSupport();

        $encrypted = call_user_func_array(
            $this->encrypt,
            [$message, $this->additionalData, $nonce, $key]
        );

        if ($this->isBinary) {
            return $encrypted;
        }

        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Decrypt the encrypted data
     *
     * @param string $encrypted The encrypted message
     * @param string $key The key to decrypt with
     * @param string $nonce The nounce used during encryption
     * @return mixed
     * @throws SodiumException
     * @throws Exception
     */
    public function decrypt(string $encrypted, string $key, string $nonce): mixed
    {
        $this->checkSupport();

        if (!$this->isBinary) {
            $encrypted = sodium_base642bin($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }

        return call_user_func_array(
            $this->decrypt,
            [$encrypted, $this->additionalData, $nonce, $key]
        );
    }

    /**
     * Retrieves the key and nonce for the encryption algorithm.
     *
     * @return array Returns an array containing the key and nonce.
     * @throws Exception
     */
    public function getKey(): array
    {
        $this->checkSupport();
        return [
            'key' => call_user_func($this->keygen),
            'nonce' => random_bytes($this->availableAlgorithms[$this->algorithm]),
        ];
    }

    /**
     * Checks if the specified algorithm is supported.
     *
     * @return void
     * @throws Exception if the algorithm is not supported
     */
    private function checkSupport(): void
    {
        if (!isset($this->availableAlgorithms[$this->algorithm])) {
            throw new Exception(
                "Invalid algorithm! Available: " . implode(', ', array_keys($this->availableAlgorithms))
            );
        }

        if ($this->algorithm === 'aes256gcm' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new Exception('Hardware accelerated AES not available!');
        }
    }
}
