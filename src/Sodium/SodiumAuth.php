<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumAuth
{
    use Base64Codec;

    /**
     * Constructor for the SodiumAuth class.
     *
     * @param bool $isMessageBinary (optional) Whether the authentication result should be in binary format.
     * @param bool $isSecretBinary Secret is binary?
     */
    public function __construct(
        private bool $isMessageBinary = false,
        private bool $isSecretBinary = false,
    ) {}

    /**
     * Compute the authenticity of a message.
     *
     * @param string $message The message to be authenticated.
     * @param string $secret The secret key used for authenticity.
     * @return string The computed authentication in binary format or base64-encoded format.
     *
     * @throws SodiumException
     */
    public function compute(string $message, #[\SensitiveParameter] string $secret): string
    {
        if (!$this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
        }
        $authTag = sodium_crypto_auth($message, $secret);

        return $this->isMessageBinary ? $authTag : $this->bin2base64($authTag);
    }

    /**
     * Verify the authenticity of a message using provided signature.
     *
     * @param string $message The message to verify.
     * @param string $secret The secret key used for authenticity.
     * @param string $signature The signature to verify against.
     * @return bool Returns true if the message is authentic, false otherwise.
     *
     * @throws SodiumException|SodiumCryptoException
     */
    public function verify(
        string $message,
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        string $signature,
    ): bool {
        if (!$this->isMessageBinary) {
            $signature = $this->base642bin($signature);
        }
        if (!$this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
        }

        return sodium_crypto_auth_verify($signature, $message, $secret);
    }

    /**
     * Generate a cryptographic authentication key.
     *
     * @return string The generated authentication key.
     *
     * @throws SodiumException
     */
    public function generateSecret(): string
    {
        $secret = sodium_crypto_auth_keygen();

        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }
}
