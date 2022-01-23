<?php

namespace AbmmHasan\SafeGuard\Symmetric\Sodium;

use SodiumException;

class SodiumAuth
{

    public function __construct(
        private string $secret,
        private bool   $isBinary = true
    )
    {

    }

    /**
     * @param $message
     * @return string
     * @throws SodiumException
     */
    public function sign($message): string
    {
        $encrypted = sodium_crypto_auth($message, $this->secret);
        if ($this->isBinary) {
            return $encrypted;
        }
        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * @param $message
     * @param $signature
     * @return bool
     * @throws SodiumException
     */
    public function verify($message, $signature): bool
    {
        if (!$this->isBinary) {
            $message = sodium_base642bin($message, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }
        if (sodium_crypto_auth_verify($signature, $message, $this->secret)) {
            return true;
        }
        return false;
    }
}
