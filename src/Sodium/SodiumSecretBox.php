<?php

namespace Infocyph\Epicrypt\Sodium;

use Exception;
use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumSecretBox
{
    use Base64Codec;
    /**
     * Constructor for the class.
     *
     * @param bool $isMessageBinary (optional) Whether the message is in binary format. Default is false.
     * @param bool $isSecretBinary (optional) Whether the secret is in binary format. Default is false.
     */
    public function __construct(
        private bool $isMessageBinary = false,
        private bool $isSecretBinary = false,
    ) {}

    /**
     * Encrypts the given message using the specified secret and nonce.
     *
     * @param string $message The message to be encrypted.
     * @param string $secret The secret key used for encryption.
     * @param string $nonce The nonce used for encryption (must be unique per message).
     * @return string The encrypted message in binary format if $isMessageBinary is true, otherwise in base64 format.
     * @throws SodiumException
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $message,
        #[\SensitiveParameter]
        string $secret,
        string $nonce,
    ): string {
        if (!$this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
            $nonce = $this->base642binSodium($nonce);
        }
        $encrypted = sodium_crypto_secretbox($message, $nonce, $secret);
        if ($this->isMessageBinary) {
            return $encrypted;
        }
        return $this->bin2base64($encrypted);
    }

    /**
     * Decrypts an encrypted message using the specified secret and nonce.
     *
     * @param string $encryptedMessage The encrypted message to be decrypted.
     * @param string $secret The secret key used for decryption.
     * @param string $nonce The nonce used for decryption (must be the same as the one used for encryption).
     * @return string|bool The decrypted message in binary format if $isMessageBinary is true, otherwise in base64 format. Returns false if decryption fails.
     * @throws SodiumException
     * @throws SodiumCryptoException
     */
    public function decrypt(string $encryptedMessage, #[\SensitiveParameter] string $secret, string $nonce): string|bool
    {
        if (!$this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
            $nonce = $this->base642binSodium($nonce);
        }
        if (!$this->isMessageBinary) {
            $encryptedMessage = $this->base642bin($encryptedMessage);
        }
        return sodium_crypto_secretbox_open($encryptedMessage, $nonce, $secret);
    }

    /**
     * Generates a random nonce.
     *
     * @return string The generated nonce.
     * @throws SodiumException|Exception
     */
    public function generateNonce(): string
    {
        $secret = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }

    /**
     * Generates a secret key.
     *
     * @return string The generated secret key.
     * @throws SodiumException
     */
    public function generateSecret(): string
    {
        $secret = sodium_crypto_secretbox_keygen();
        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }
}
