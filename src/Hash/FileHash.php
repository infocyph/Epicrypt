<?php

namespace AbmmHasan\SafeGuard\Hash;

use AbmmHasan\SafeGuard\Misc\ReadFile;
use Exception;

class FileHash
{
    public function __construct(
        private string $algorithm,
        private int $blockSize = 1024,
        private int $hashLength = SODIUM_CRYPTO_GENERICHASH_BYTES
    ) {
    }

    /**
     * Generate hash for a given file
     *
     * @param string $filePath
     * @param string $secret
     * @return false|string
     * @throws Exception
     */
    public function generate(string $filePath, string $secret = ''): bool|string
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            throw new Exception("Invalid file path!");
        }
        return match ($this->algorithm) {
            'blake2b' => sodium_bin2hex($this->chunkedGenericHash($filePath, $secret)),
            default => match (true) {
                empty($secret) => hash_file($this->algorithm, $filePath),
                default => hash_hmac_file($this->algorithm, $filePath, $secret)
            }
        };
    }

    /**
     * Generate hash in chunk
     *
     * @param string $filePath
     * @param string $secret
     * @return string
     * @throws Exception
     */
    private function chunkedGenericHash(string $filePath, string $secret): string
    {
        $fileObject = new ReadFile($filePath, 'rb');
        $context = sodium_crypto_generichash_init($secret, $this->hashLength);
        foreach ($fileObject->binary($this->blockSize) as $chunk) {
            sodium_crypto_generichash_update($context, $chunk);
        }
        return sodium_crypto_generichash_final($context, $this->hashLength);
    }
}
