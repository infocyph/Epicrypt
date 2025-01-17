<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final readonly class SodiumStringHash
{
    use Base64Codec;

    /**
     * Constructs a new instance of the class.
     *
     * @param string $algorithm The hash algorithm to use. Default is 'blake2b'.
     * @param bool $isHashBinary Whether the generated hash is binary or not. Default is false.
     * @param bool $isSecretBinary Whether the secret key is binary or not. Default is false.
     * @param int $hashLength The length of the generated hash. Default is 32. Utilized for 'blake2b'.
     */
    public function __construct(
        private string $algorithm = 'blake2b',
        private bool $isHashBinary = false,
        private bool $isSecretBinary = false,
        private int $hashLength = SODIUM_CRYPTO_GENERICHASH_BYTES,
    ) {}

    /**
     * Generates a hash for a given string using the specified algorithm and secret key.
     *
     * @param string $data The string to be hashed.
     * @param string|null $secret The secret key used for hashing. Default is null.
     * @return string The generated hash.
     * @throws SodiumCryptoException|SodiumException
     */
    public function generate(#[\SensitiveParameter] string $data, #[\SensitiveParameter] string $secret = null): string
    {
        if (!empty($secret) && !$this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
        }
        $hash = match ($this->algorithm) {
            'sip' => sodium_crypto_shorthash($data, $secret),
            'blake2b' => sodium_crypto_generichash($data, $secret ?: '', $this->hashLength),
            default => throw new SodiumCryptoException("Unsupported hash algorithm, Available: sip, blake2b"),
        };

        return $this->isHashBinary ? $hash : bin2hex($hash);
    }

    /**
     * Retrieves the secret key for the specified hash algorithm.
     *
     * @return string The secret key for the hash algorithm.
     * @throws SodiumCryptoException|SodiumException
     */
    public function generateSecret(): string
    {
        $secret = match ($this->algorithm) {
            'sip' => sodium_crypto_shorthash_keygen(),
            'blake2b' => sodium_crypto_generichash_keygen(),
            default => throw new SodiumCryptoException("Unsupported hash algorithm, Available: sip, blake2b"),
        };
        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }

    /**
     * Verifies the given hash against the generated hash for the given data using the specified secret.
     *
     * @param string $hash The expected hash value.
     * @param string $data The data to be hashed.
     * @param string|null $secret The secret key used for hashing. Default is null.
     * @return bool Returns true if the generated hash matches the expected hash, false otherwise.
     * @throws SodiumCryptoException|SodiumException
     */
    public function verify(
        string $hash,
        #[\SensitiveParameter]
        string $data,
        #[\SensitiveParameter]
        string $secret = null,
    ): bool {
        return hash_equals($hash, $this->generate($data, $secret));
    }
}
