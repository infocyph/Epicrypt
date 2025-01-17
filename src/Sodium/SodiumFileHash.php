<?php

namespace Infocyph\Epicrypt\Sodium;

use Exception;
use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use Infocyph\Epicrypt\Misc\ReadFile;
use SodiumException;

final class SodiumFileHash
{
    use Base64Codec;

    private array $algoFunctionMap = [
        'blake2b' => 'chunkedGenericHash',
    ];

    /**
     * Constructs a new instance of the class.
     *
     * @param  string  $algorithm  The hash algorithm to use. Default is 'blake2b'.
     * @param  int  $blockSize  The block size for hashing. Default is 1024.
     * @param  bool  $isHashBinary  Whether the generated hash is binary or not. Default is false.
     * @param  bool  $isSecretBinary  Whether the secret key is binary or not. Default is false.
     * @param  int  $hashLength  The length of the generated hash. Default is SODIUM_CRYPTO_GENERICHASH_BYTES.
     */
    public function __construct(
        private readonly string $algorithm = 'blake2b',
        private readonly int $blockSize = 1024,
        private readonly bool $isHashBinary = false,
        private readonly bool $isSecretBinary = false,
        private readonly int $hashLength = SODIUM_CRYPTO_GENERICHASH_BYTES,
    ) {}

    /**
     * Generates a hash for a given file using the specified algorithm and secret key.
     *
     * @param  string  $filePath  The path to the file to be hashed.
     * @param  string  $secret  The secret key used for hashing. Default is an empty string.
     * @return string The hash value
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function generate(string $filePath, #[\SensitiveParameter] string $secret = ''): string
    {
        if (! isset($this->algoFunctionMap[$this->algorithm])) {
            throw new SodiumCryptoException(
                'Invalid algorithm! Available: '.implode(', ', array_keys($this->algoFunctionMap)),
            );
        }
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            throw new SodiumCryptoException('Invalid file path!');
        }
        if (! empty($secret) && ! $this->isSecretBinary) {
            $secret = $this->base642binSodium($secret);
        }
        $hash = $this->{$this->algoFunctionMap[$this->algorithm]}($filePath, $secret);

        return $this->isHashBinary ? $hash : bin2hex($hash);
    }

    /**
     * Verifies the hash of a file against the generated hash using the given secret.
     *
     * @param  string  $hash  The expected hash value.
     * @param  string  $filePath  The path to the file to be verified.
     * @param  string  $secret  The secret key used for generating the hash. Default is an empty string.
     * @return bool Returns true if the hash of the file matches the expected hash, false otherwise.
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function verify(
        string $hash,
        string $filePath,
        #[\SensitiveParameter]
        string $secret = '',
    ): bool {
        return hash_equals($hash, $this->generate($filePath, $secret));
    }

    /**
     * Retrieves the secret key for the specified hash algorithm.
     *
     * @return string The secret key for the hash algorithm.
     *
     * @throws SodiumCryptoException|SodiumException
     */
    public function generateSecret(): string
    {
        $secret = match ($this->algorithm) {
            'blake2b' => sodium_crypto_generichash_keygen(),
            default => throw new SodiumCryptoException(
                'Invalid algorithm! Available: '.implode(', ', array_keys($this->algoFunctionMap)),
            ),
        };

        return $this->isSecretBinary ? $secret : $this->bin2base64Sodium($secret);
    }

    /**
     * Calculates the chunked generic hash of a given file using the provided secret.
     *
     * @param  string  $filePath  The path to the file to be hashed.
     * @param  string  $secret  The secret key used for hashing.
     * @return string The final hash value.
     *
     * @throws SodiumException|Exception
     */
    private function chunkedGenericHash(string $filePath, #[\SensitiveParameter] string $secret): string
    {
        $fileObject = new ReadFile($filePath, 'rb');
        $context = sodium_crypto_generichash_init($secret, $this->hashLength);
        foreach ($fileObject->binary($this->blockSize) as $chunk) {
            sodium_crypto_generichash_update($context, $chunk);
        }

        return sodium_crypto_generichash_final($context, $this->hashLength);
    }
}
