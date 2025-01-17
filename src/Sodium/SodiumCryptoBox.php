<?php

namespace Infocyph\Epicrypt\Sodium;

use Exception;
use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumCryptoBox
{
    use Base64Codec;

    /**
     * @param bool $isMessageBinary (optional) Message in binary format?
     * @param bool $isSecretBinary Secrets(Third party public key, Own private key, Shared secret) are binary?
     */
    public function __construct(
        private bool $isMessageBinary = false,
        private bool $isSecretBinary = false,
    ) {}

    /**
     * Encrypt the message
     *
     * @param string $message Message for encryption
     * @param string $thirdPartyPublicKey Third party public key
     * @param string $ownPrivateKey Own private key
     * @param string $sharedSecret Shared secret (only used once per message)
     * @return string Encrypted message
     * @throws SodiumException
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $message,
        #[\SensitiveParameter]
        string $thirdPartyPublicKey,
        #[\SensitiveParameter]
        string $ownPrivateKey,
        string $sharedSecret,
    ): string {
        if (!$this->isSecretBinary) {
            $thirdPartyPublicKey = $this->base642binSodium($thirdPartyPublicKey);
            $ownPrivateKey = $this->base642binSodium($ownPrivateKey);
            $sharedSecret = $this->base642binSodium($sharedSecret);
        }

        $encrypted = sodium_crypto_box(
            $message,
            $sharedSecret,
            sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $ownPrivateKey,
                $thirdPartyPublicKey,
            ),
        );

        return $this->isMessageBinary ? $encrypted : $this->bin2base64($encrypted);
    }

    /**
     * Decrypt the message
     *
     * @param string $encryptedMessage Encrypted message
     * @param string $thirdPartyPublicKey Third party public key
     * @param string $ownPrivateKey Own private key
     * @param string $sharedSecret Shared secret
     * @return false|string Decrypted message
     * @throws SodiumException
     */
    public function decrypt(
        string $encryptedMessage,
        #[\SensitiveParameter]
        string $thirdPartyPublicKey,
        #[\SensitiveParameter]
        string $ownPrivateKey,
        string $sharedSecret,
    ): bool|string {
        if (!$this->isMessageBinary) {
            $encryptedMessage = $this->base642bin($encryptedMessage);
        }
        if (!$this->isSecretBinary) {
            $thirdPartyPublicKey = $this->base642binSodium($thirdPartyPublicKey);
            $ownPrivateKey = $this->base642binSodium($ownPrivateKey);
            $sharedSecret = $this->base642binSodium($sharedSecret);
        }

        return sodium_crypto_box_open(
            $encryptedMessage,
            $sharedSecret,
            sodium_crypto_box_keypair_from_secretkey_and_publickey(
                $ownPrivateKey,
                $thirdPartyPublicKey,
            ),
        );
    }

    /**
     * Generates a secret key pair for the Sodium Crypto Box algorithm.
     *
     * @param string|null $seed (optional) Seed for deterministic key generation. If provided, it must be 32 bytes long.
     * @return array An array containing the private key, public key and shared key.
     * @throws SodiumCryptoException|SodiumException|Exception
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
            'private' => sodium_crypto_box_secretkey($keypair),
            'public' => sodium_crypto_box_publickey($keypair),
        ];

        if ($this->isSecretBinary) {
            return $keys;
        }

        return [
            'private' => $this->bin2base64Sodium($keys['private']),
            'public' => $this->bin2base64Sodium($keys['public']),
        ];
    }

    /**
     * Generates a shared secret
     *
     * @return string The generated shared secret.
     * @throws SodiumException|Exception
     */
    public function generateSharedSecret(): string
    {
        $secret = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }
}
