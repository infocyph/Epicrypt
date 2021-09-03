<?php

namespace AbmmHasan\SafeGuard\Asymmetric;

use SodiumException;

class SodiumSign
{
    public function __construct(
        private bool   $isBinary = true
    )
    {

    }

    /**
     * Sign a message
     *
     * @param string $message Message to sign
     * @param string $privateKey Secret key
     * @return string Signed message
     * @throws SodiumException
     */
    public function getSignedMessage(string $message, string $privateKey): string
    {
        $encrypted = sodium_crypto_sign($message, $privateKey);

        if ($this->isBinary) {
            return $encrypted;
        }

        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Verify attached signature and get the message
     *
     * @param string $signedMessage Signed message
     * @param string $publicKey Public key
     * @return false|string Signature verified message
     * @throws SodiumException
     */
    public function getVerifiedMessage(string $signedMessage, string $publicKey): bool|string
    {
        if (!$this->isBinary) {
            $signedMessage = sodium_base642bin($signedMessage, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }

        return sodium_crypto_sign_open($signedMessage, $publicKey);
    }


}
