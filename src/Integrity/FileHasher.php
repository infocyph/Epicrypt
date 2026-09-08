<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Exception\Integrity\HashingException;
use Infocyph\Epicrypt\Internal\StreamIO;

final readonly class FileHasher
{
    private const int STREAM_CHUNK_SIZE = 64 * 1024;

    public function __construct(private IntegrityAlgorithm $algorithm = IntegrityAlgorithm::SHA256) {}

    public function hash(string $path, bool $binary = false, ?int $length = null): string
    {
        try {
            return StreamIO::withReadableLocalFile(
                $path,
                fn($stream): string => $this->hashStream($stream, $binary, $length),
            );
        } catch (HashingException|FileAccessException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new FileAccessException('Unable to hash file: ' . $path, 0, $exception);
        }
    }

    /**
     * Hash from the current stream position through EOF. The caller owns the stream lifecycle.
     *
     * @param resource $stream
     */
    public function hashStream(mixed $stream, bool $binary = false, ?int $length = null): string
    {
        StreamIO::assertReadable($stream);

        return $this->algorithm === IntegrityAlgorithm::BLAKE2B
            ? $this->hashBlake2b($stream, $binary, $length)
            : $this->hashPhp($stream, $binary, $length);
    }

    public function verify(
        string $path,
        #[\SensitiveParameter]
        string $digest,
        bool $binary = false,
        ?int $length = null,
    ): bool {
        if (!$this->digestIsWellFormed($digest, $binary, $length)) {
            return false;
        }

        return hash_equals($this->hash($path, $binary, $length), $digest);
    }

    /**
     * Verify from the current stream position through EOF. The caller owns the stream lifecycle.
     *
     * @param resource $stream
     */
    public function verifyStream(
        mixed $stream,
        #[\SensitiveParameter]
        string $digest,
        bool $binary = false,
        ?int $length = null,
    ): bool {
        if (!$this->digestIsWellFormed($digest, $binary, $length)) {
            return false;
        }

        return hash_equals($this->hashStream($stream, $binary, $length), $digest);
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

    private function digestIsWellFormed(string $digest, bool $binary, ?int $length): bool
    {
        $expectedBytes = $this->algorithm === IntegrityAlgorithm::BLAKE2B
            ? $this->blake2bLength($length)
            : strlen(hash($this->algorithm->value, '', true));

        return $binary
            ? strlen($digest) === $expectedBytes
            : strlen($digest) === $expectedBytes * 2 && ctype_xdigit($digest);
    }

    /** @param resource $stream */
    private function hashBlake2b(mixed $stream, bool $binary, ?int $length): string
    {
        $outputLength = $this->blake2bLength($length);
        $state = sodium_crypto_generichash_init('', $outputLength);

        try {
            while (($chunk = StreamIO::readChunk($stream, self::STREAM_CHUNK_SIZE)) !== null) {
                sodium_crypto_generichash_update($state, $chunk);
            }
            $digest = sodium_crypto_generichash_final($state, $outputLength);

            return $binary ? $digest : sodium_bin2hex($digest);
        } finally {
            if (is_string($state)) {
                sodium_memzero($state);
            }
        }
    }

    /** @param resource $stream */
    private function hashPhp(mixed $stream, bool $binary, ?int $length): string
    {
        if ($length !== null) {
            throw new HashingException('Digest length is configurable only for BLAKE2b.');
        }

        $context = hash_init($this->algorithm->value);
        while (($chunk = StreamIO::readChunk($stream, self::STREAM_CHUNK_SIZE)) !== null) {
            hash_update($context, $chunk);
        }

        return hash_final($context, $binary);
    }
}
