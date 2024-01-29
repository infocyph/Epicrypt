<?php

namespace AbmmHasan\SafeGuard\Symmetric\Sodium;

use Exception;
use SodiumException;

class SodiumSecretBox
{

    public function __construct(
        private string $key,
        private string $nonce,
        private bool $isBinary = true
    ) {
    }

    /**
     * @param string $message
     * @return string
     * @throws SodiumException
     */
    public function encrypt(string $message): string
    {
        $encrypted = sodium_crypto_secretbox($message, $this->nonce, $this->key);
        if ($this->isBinary) {
            return $encrypted;
        }
        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * @param string $encryptedMessage
     * @return string|bool
     * @throws SodiumException
     */
    public function decrypt(string $encryptedMessage): string|bool
    {
        if (!$this->isBinary) {
            $encryptedMessage = sodium_base642bin($encryptedMessage, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }
        return sodium_crypto_secretbox_open($encryptedMessage, $this->nonce, $this->key);
    }

    /**
     * Sodium Secret Box keygen (Symmetric)
     *
     * @return object Key resource
     * @throws Exception
     */
    public static function secretBox(): object
    {
        return (object)[
            'key' => sodium_crypto_secretbox_keygen(),
            'nonce' => random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES)
        ];
    }
}
