<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumSign
{
    use Base64Codec;

    /**
     * Constructor for the SodiumSign class.
     *
     * @param bool $isMessageBinary (optional) Whether the message is in binary format.
     * @param bool $isSecretBinary (optional) Whether the secret is in binary format.
     */
    public function __construct(
        private bool $isMessageBinary = false,
        private bool $isSecretBinary = false,
    ) {}

    /**
     * Signs a message using the Sodium Sign algorithm and returns the signature.
     *
     * @param string $message The message to sign.
     * @param string $privateKey The private key used for signing.
     * @return string The signed message.
     * @throws SodiumException
     */
    public function detachedSign(
        string $message,
        #[\SensitiveParameter] string $privateKey,
    ): string {
        if (!$this->isSecretBinary) {
            $privateKey = $this->base642binSodium($privateKey);
        }

        $signature = sodium_crypto_sign_detached($message, $privateKey);

        if ($this->isMessageBinary) {
            return $signature;
        }
        return $this->bin2base64($signature);
    }

    /**
     * Verifies a detached signature using the Sodium Sign algorithm.
     *
     * @param string $message The message to verify.
     * @param string $signature The signature to verify with.
     * @param string $publicKey The public key for verification.
     * @return bool Returns true if the signature is valid, false otherwise.
     * @throws SodiumException
     * @throws SodiumCryptoException
     */
    public function verifyDetachedSign(
        string $message,
        string $signature,
        #[\SensitiveParameter]
        string $publicKey,
    ): bool {
        if (!$this->isSecretBinary) {
            $publicKey = $this->base642binSodium($publicKey);
            $signature = $this->base642binSodium($signature);
        }
        if (!$this->isMessageBinary) {
            $message = $this->base642bin($message, true);
        }
        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }

    /**
     * Sign a message using the Sodium Sign algorithm.
     *
     * @param string $message The message to sign.
     * @param string $privateKey The private key used for signing.
     * @return string The signed message.
     * @throws SodiumException
     */
    public function attachedSign(
        string $message,
        #[\SensitiveParameter]
        string $privateKey,
    ): string {
        if (!$this->isSecretBinary) {
            $privateKey = $this->base642binSodium($privateKey);
        }

        $signed = sodium_crypto_sign($message, $privateKey);

        if ($this->isMessageBinary) {
            return $signed;
        }
        return $this->bin2base64($signed);
    }

    /**
     * Verifies an attached signature using the Sodium Sign algorithm.
     *
     * @param string $signedMessage The signed message to verify.
     * @param string $publicKey The public key for verification.
     * @return false|string Returns message if the signature is valid, false otherwise.
     * @throws SodiumException
     * @throws SodiumCryptoException
     */
    public function verifyAttachedSign(string $signedMessage, #[\SensitiveParameter] string $publicKey): false|string
    {
        if (!$this->isMessageBinary) {
            $signedMessage = $this->base642bin($signedMessage);
        }

        if (!$this->isSecretBinary) {
            $publicKey = $this->base642binSodium($publicKey);
        }

        return sodium_crypto_sign_open($signedMessage, $publicKey);
    }

    /**
     * Generates a secret key pair for the Sodium Sign algorithm.
     *
     * @param string|null $seed (optional) Seed for deterministic key generation.
     * @return array An array containing the private key and public key.
     * @throws SodiumCryptoException|SodiumException
     */
    public function generateSecretPair(string $seed = null): array
    {
        if (!is_null($seed)) {
            if (($length = strlen($seed)) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                throw new SodiumCryptoException(
                    "Invalid Seed size (Expected: " . SODIUM_CRYPTO_SIGN_SEEDBYTES . "B, Found: {$length}B)!",
                );
            }
            $keypair = sodium_crypto_sign_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_sign_keypair();
        }

        $keys = [
            'private' => sodium_crypto_sign_secretkey($keypair),
            'public' => sodium_crypto_sign_publickey($keypair),
        ];

        if ($this->isSecretBinary) {
            return $keys;
        }

        return [
            'private' => $this->bin2base64Sodium($keys['private']),
            'public' => $this->bin2base64Sodium($keys['public']),
        ];
    }
}
