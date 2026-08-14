<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Exception\Integrity\HashingException;
use Infocyph\Pathwise\FileManager\SafeFileReader;

final readonly class FileHasher
{
    public function __construct(private IntegrityAlgorithm $algorithm = IntegrityAlgorithm::SHA256) {}

    public function hash(string $path, bool $binary = false, ?int $length = null): string
    {
        $reader = new SafeFileReader($path);

        try {
            return $this->algorithm === IntegrityAlgorithm::BLAKE2B
                ? $this->hashBlake2b($reader, $binary, $length)
                : $this->hashPhp($reader, $binary, $length);
        } catch (HashingException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new FileAccessException('Unable to hash file: ' . $path, 0, $exception);
        } finally {
            $reader->releaseLock();
        }
    }

    public function verify(string $path, string $digest, bool $binary = false, ?int $length = null): bool
    {
        $expectedBytes = $this->algorithm === IntegrityAlgorithm::BLAKE2B
            ? $this->blake2bLength($length)
            : strlen(hash($this->algorithm->value, '', true));
        if ($binary ? strlen($digest) !== $expectedBytes : strlen($digest) !== $expectedBytes * 2 || !ctype_xdigit($digest)) {
            return false;
        }

        return hash_equals($this->hash($path, $binary, $length), $digest);
    }

    private function blake2bLength(?int $length): int
    {
        $length ??= SODIUM_CRYPTO_GENERICHASH_BYTES;
        if ($length < SODIUM_CRYPTO_GENERICHASH_BYTES_MIN || $length > SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new HashingException(sprintf(
                'BLAKE2b length must be between %d and %d bytes.',
                SODIUM_CRYPTO_GENERICHASH_BYTES_MIN,
                SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
            ));
        }

        return $length;
    }

    private function hashBlake2b(SafeFileReader $reader, bool $binary, ?int $length): string
    {
        $outputLength = $this->blake2bLength($length);
        $state = sodium_crypto_generichash_init('', $outputLength);
        foreach ($reader->chunks() as $chunk) {
            sodium_crypto_generichash_update($state, $chunk);
        }
        $digest = sodium_crypto_generichash_final($state, $outputLength);

        return $binary ? $digest : sodium_bin2hex($digest);
    }

    private function hashPhp(SafeFileReader $reader, bool $binary, ?int $length): string
    {
        if ($length !== null) {
            throw new HashingException('Digest length is configurable only for BLAKE2b.');
        }

        $context = hash_init($this->algorithm->value);
        foreach ($reader->chunks() as $chunk) {
            hash_update($context, $chunk);
        }

        return hash_final($context, $binary);
    }
}
