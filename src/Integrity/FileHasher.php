<?php

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Exception\Integrity\HashingException;
use Infocyph\Epicrypt\Internal\SecureCompare;

final readonly class FileHasher
{
    public function __construct(
        private string $algorithm = 'sha256',
    ) {}

    public function hash(string $path, string $key = ''): string
    {
        if (! file_exists($path) || ! is_readable($path)) {
            throw new FileAccessException('Invalid file path: ' . $path);
        }

        if ($this->algorithm === 'blake2b') {
            $stream = fopen($path, 'rb');
            if ($stream === false) {
                throw new FileAccessException('Unable to open file: ' . $path);
            }

            try {
                $state = sodium_crypto_generichash_init($key);
                while (! feof($stream)) {
                    $chunk = fread($stream, 8192);
                    if ($chunk === false) {
                        throw new FileAccessException('Unable to read file: ' . $path);
                    }

                    if ($chunk !== '') {
                        sodium_crypto_generichash_update($state, $chunk);
                    }
                }

                return sodium_bin2hex(sodium_crypto_generichash_final($state));
            } finally {
                fclose($stream);
            }
        }

        if (! in_array($this->algorithm, hash_algos(), true)) {
            throw new HashingException('Unsupported hash algorithm: ' . $this->algorithm);
        }

        $hash = $key === ''
            ? hash_file($this->algorithm, $path)
            : hash_hmac_file($this->algorithm, $path, $key);

        if (! is_string($hash)) {
            throw new HashingException('File hashing failed.');
        }

        return $hash;
    }

    public function verify(string $path, string $digest, string $key = ''): bool
    {
        return SecureCompare::equals($digest, $this->hash($path, $key));
    }
}
