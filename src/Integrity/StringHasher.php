<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Exception\Integrity\HashingException;

final readonly class StringHasher
{
    public function __construct(private IntegrityAlgorithm $algorithm = IntegrityAlgorithm::SHA256) {}

    public function hash(string $data, bool $binary = false, ?int $length = null): string
    {
        if ($this->algorithm !== IntegrityAlgorithm::BLAKE2B) {
            if ($length !== null) {
                throw new HashingException('Digest length is configurable only for BLAKE2b.');
            }

            return hash($this->algorithm->value, $data, $binary);
        }

        $outputLength = $this->blake2bLength($length);
        $digest = sodium_crypto_generichash($data, '', $outputLength);

        return $binary ? $digest : sodium_bin2hex($digest);
    }

    public function verify(string $data, string $digest, bool $binary = false, ?int $length = null): bool
    {
        $expectedBytes = $this->algorithm === IntegrityAlgorithm::BLAKE2B
            ? $this->blake2bLength($length)
            : strlen(hash($this->algorithm->value, '', true));
        if (!$this->isWellFormedDigest($digest, $binary, $expectedBytes)) {
            return false;
        }

        return hash_equals($this->hash($data, $binary, $length), $digest);
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

    private function isWellFormedDigest(string $digest, bool $binary, int $expectedBytes): bool
    {
        return $binary
            ? strlen($digest) === $expectedBytes
            : strlen($digest) === $expectedBytes * 2 && ctype_xdigit($digest);
    }
}
