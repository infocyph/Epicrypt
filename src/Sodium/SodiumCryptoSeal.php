<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumCryptoSeal
{
    use Base64Codec;

    /**
     * Set predefined property
     *
     * @param bool $isMessageBinary Is transportable resource binary?
     * @param bool $isSecretBinary Secrets(public key, key pair) are binary?
     */
    public function __construct(
        private bool $isMessageBinary = false,
        private bool $isSecretBinary = false,
    ) {}

    /**
     * Encrypt the message (using recipient public key)
     *
     * @param string $message Message for encryption
     * @param string $publicKey Public key
     * @return string Encrypted message
     * @throws SodiumException
     */
    public function encrypt(#[\SensitiveParameter] string $message, string $publicKey): string
    {
        if (!$this->isSecretBinary) {
            $publicKey = $this->base642binSodium($publicKey);
        }

        $encrypted = sodium_crypto_box_seal($message, $publicKey);

        return $this->isMessageBinary ? $encrypted : $this->bin2base64($encrypted);
    }

    /**
     * Decrypt the message (using recipient keypair)
     *
     * @param string $encrypted Encrypted message
     * @param string $keypair The keypair
     * @return false|string Decrypted message
     * @throws SodiumException|SodiumCryptoException
     */
    public function decrypt(string $encrypted, #[\SensitiveParameter] string $keypair): bool|string
    {
        if (!$this->isSecretBinary) {
            $keypair = $this->base642binSodium($keypair);
        }

        if (!$this->isMessageBinary) {
            $encrypted = $this->base642bin($encrypted);
        }

        return sodium_crypto_box_seal_open($encrypted, $keypair);
    }

    /**
     * Generates a secret key pair for the Sodium Crypto Box algorithm.
     *
     * @param string|null $seed (optional) Seed for deterministic key generation. If provided, it must be 32 bytes long.
     * @return array An array containing the keypair and public key.
     * @throws SodiumCryptoException|SodiumException
     */
    public function generateSecretPair(string $seed = null): array
    {
        if (!is_null($seed)) {
            if (($length = strlen($seed)) !== 32) {
                throw new SodiumCryptoException("Invalid Seed size (Expected: 32B, Found: {$length}B)!");
            }
            $keypair = sodium_crypto_box_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_box_keypair();
        }

        $keys = [
            'keypair' => $keypair,
            'public' => sodium_crypto_box_publickey($keypair),
        ];

        if ($this->isSecretBinary) {
            return $keys;
        }

        return [
            'keypair' => $this->bin2base64Sodium($keys['keypair']),
            'public' => $this->bin2base64Sodium($keys['public']),
        ];
    }
}
