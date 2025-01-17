<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

final class SodiumPasswordHash
{
    private array $pwdHashSettings = [
        'sodium_crypto_pwhash_str' => [
            'opsLimit' => [
                'interactive' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                'moderate' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                'sensitive' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
            ],
            'memLimit' => [
                'interactive' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                'moderate' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
                'sensitive' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
            ],
        ],
        'sodium_crypto_pwhash_scryptsalsa208sha256_str' => [
            'opsLimit' => [
                'interactive' => SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                'sensitive' => SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE,
            ],
            'memLimit' => [
                'interactive' => SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE,
                'sensitive' => SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE,
            ],
        ],
    ];

    /**
     * Constructs a new instance of the class.
     *
     * @param string $algorithm The algorithm to use for hashing (default: 'argon2id')
     * @param string $opsLimit The ops limit for the algorithm (default: 'interactive')
     * @param string $memLimit The memory limit for the algorithm (default: 'interactive')
     */
    public function __construct(
        private readonly string $algorithm = 'argon2id',
        private readonly string $opsLimit = 'interactive',
        private readonly string $memLimit = 'interactive',
    ) {}

    /**
     * Generates a hashed password using the specified algorithm.
     *
     * @param string $password The password to be hashed.
     * @return string The hashed password.
     * @throws SodiumCryptoException
     */
    public function generate(#[\SensitiveParameter] string $password): string
    {
        return match ($this->algorithm) {
            'argon2id' => $this->getHash('sodium_crypto_pwhash_str', $password),
            'scryptsalsa208sha256' => $this->getHash('sodium_crypto_pwhash_scryptsalsa208sha256_str', $password),
            default => throw new SodiumCryptoException(
                'Unsupported algorithm! Available: argon2id, scryptsalsa208sha256',
            ),
        };
    }

    /**
     * Verifies the given hash against the provided password using the specified algorithm.
     *
     * @param string $hash The hash to be verified.
     * @param string $password The password to be verified against the hash.
     * @return bool Returns true if the hash matches the password, false otherwise.
     * @throws SodiumCryptoException|SodiumException
     */
    public function verify(string $hash, #[\SensitiveParameter] string $password): bool
    {
        return match ($this->algorithm) {
            'argon2id' => sodium_crypto_pwhash_str_verify($hash, $password),
            'scryptsalsa208sha256' => sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password),
            default => throw new SodiumCryptoException(
                'Unsupported algorithm! Available: argon2id, scryptsalsa208sha256',
            ),
        };
    }

    /**
     * Generates a hash using the specified hash function and password.
     *
     * @param string $hashFunction The name of the hash function to use.
     * @param string $password The password to hash.
     * @return string The generated hash.
     * @throws SodiumCryptoException
     */
    private function getHash(string $hashFunction, #[\SensitiveParameter] string $password): string
    {
        if (!isset($this->pwdHashSettings[$hashFunction]['opsLimit'][$this->opsLimit])) {
            throw new SodiumCryptoException(
                'Invalid opsLimit! Available: ' . implode(
                    ', ',
                    array_keys($this->pwdHashSettings[$hashFunction]['opsLimit']),
                ),
            );
        }

        if (!isset($this->pwdHashSettings[$hashFunction]['memLimit'][$this->memLimit])) {
            throw new SodiumCryptoException(
                'Invalid memLimit! Available: ' . implode(
                    ', ',
                    array_keys($this->pwdHashSettings[$hashFunction]['memLimit']),
                ),
            );
        }

        return call_user_func_array(
            $hashFunction,
            [
                $password,
                $this->pwdHashSettings[$hashFunction]['opsLimit'][$this->opsLimit],
                $this->pwdHashSettings[$hashFunction]['memLimit'][$this->memLimit],
            ],
        );
    }
}
