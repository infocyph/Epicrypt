<?php

namespace AbmmHasan\SafeGuard\Symmetric;

use SodiumException;

class SodiumSecretBox
{

    public function __construct(
        private string $key,
        private string $nonce,
        private bool   $isBinary = true
    )
    {

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
        return sodium_crypto_secretbox($encryptedMessage, $this->nonce, $this->key);
    }
}
