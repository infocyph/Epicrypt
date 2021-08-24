<?php

namespace AbmmHasan\SafeGuard\Asymmetric;

use Exception;
use SodiumException;

class SodiumSeal
{

    /**
     * Set predefined property
     *
     * @param bool $isBinary Is transportable resource binary?
     */
    public function __construct(
        private bool $isBinary = true
    )
    {
    }

    /**
     * Encrypt the message (using anonymous public key)
     *
     * @param string $message Message for encryption
     * @param string $publicKey Public key
     * @return string Encrypted message
     * @throws SodiumException
     */
    public function encrypt(string $message, string $publicKey): string
    {
        $encrypted = sodium_crypto_box_seal($message, $publicKey);

        if ($this->isBinary) {
            return $encrypted;
        }

        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Decrypt the message (using anonymous public key)
     *
     * @param string $encrypted Encrypted message
     * @param string $privateKey Private key
     * @return false|string Decrypted message
     * @throws SodiumException
     */
    public function decrypt(string $encrypted, string $privateKey): bool|string
    {
        if (!$this->isBinary) {
            $encrypted = sodium_base642bin($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }

        return sodium_crypto_box_seal_open($encrypted,
            sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $privateKey,
                sodium_crypto_box_publickey_from_secretkey($privateKey)
            ));
    }

    /**
     * Get private key
     *
     * @param string|null $seed (optional) Seed for deterministic key generation
     * @return string Key resource
     * @throws SodiumException
     * @throws Exception
     */
    public static function getKeypair(string $seed = null): string
    {
        if (!is_null($seed)) {
            if (($length = strlen($seed)) !== 32) {
                throw new Exception("Invalid Seed size (Expected: 32B, Found: {$length}B)!");
            }
            $keypair = sodium_crypto_box_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_box_keypair();
        }

        return (object)[
            'private' => sodium_crypto_box_secretkey($keypair),
            'public' => sodium_crypto_box_publickey($keypair)
        ];
    }
}
