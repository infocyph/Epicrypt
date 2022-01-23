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
     * @param string $additionalData
     * @param string $algorithm
     * @param bool $isBinary
     */
    public function __construct(
        private string $additionalData,
        private string $algorithm = 'xchacha20poly1305_ietf',
        private bool   $isBinary = true
    )
    {
        $this->keygen = "sodium_crypto_aead_{$this->algorithm}_keygen";
        $this->encrypt = "sodium_crypto_aead_{$this->algorithm}_encrypt";
        $this->decrypt = "sodium_crypto_aead_{$this->algorithm}_decrypt";
    }

    /**
     * Encrypt data
     *
     * @param string $message
     * @param string $key
     * @param string $nonce
     * @return mixed
     * @throws SodiumException
     * @throws Exception
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
     * @param string $encrypted
     * @param string $key
     * @param string $nonce
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
     * @return array
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
     * @throws Exception
     */
    private function checkSupport()
    {
        if (!isset($this->availableAlgorithms[$this->algorithm])) {
            throw new Exception("Invalid algorithm! Available: " . implode(', ', array_keys($this->availableAlgorithms)));
        }

        if ($this->algorithm === 'aes256gcm' && !sodium_crypto_aead_aes256gcm_is_available()) {
            throw new Exception('Hardware accelerated AES not available!');
        }
    }
}
