<?php

namespace AbmmHasan\SafeGuard\Asymmetric;

use Exception;
use SodiumException;

class SodiumBox
{
    /**
     * @param string $privateKey User private key
     * @param string $nonce Shared secret
     * @param bool $isBinary Is transportable resource binary?
     */
    public function __construct(
        private string $privateKey,
        private string $nonce,
        private bool   $isBinary = true
    )
    {
    }

    /**
     * Encrypt the message
     *
     * @param string $message Message for encryption
     * @param string $publicKey Second party public key
     * @return string Encrypted message
     * @throws SodiumException
     */
    public function encrypt(string $message, string $publicKey): string
    {
        $encrypted = sodium_crypto_box(
            $message,
            $this->nonce,
            sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $this->privateKey,
                $publicKey
            )
        );

        if ($this->isBinary) {
            return $encrypted;
        }

        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Decrypt the message
     *
     * @param string $encrypted Encrypted message
     * @param string $publicKey Second party public key
     * @return false|string Decrypted message
     * @throws SodiumException
     */
    public function decrypt(string $encrypted, string $publicKey): bool|string
    {
        if (!$this->isBinary) {
            $encrypted = sodium_base642bin($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }

        return sodium_crypto_box_open(
            $encrypted,
            $this->nonce,
            sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $this->privateKey,
                $publicKey
            )
        );
    }

    /**
     * Get a key pair & nonce
     *
     * @param string|null $seed (optional) Seed for deterministic key generation
     * @return object Key resource
     * @throws SodiumException
     * @throws Exception
     */
    public static function getKeypair(string $seed = null): object
    {
        if (!is_null($seed)) {
            if ($length = strlen($seed) !== 32) {
                throw new Exception("Invalid Seed size (Expected: 32B, Found: {$length}B)!");
            }
            $keypair = sodium_crypto_box_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_box_keypair();
        }

        return (object)[
            'private' => sodium_crypto_box_secretkey($keypair),
            'public' => sodium_crypto_box_publickey($keypair),
            'nonce' => random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES)
        ];
    }
}
