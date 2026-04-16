<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Exception\Integrity\HashingException;
use Infocyph\Epicrypt\Integrity\Contract\HasherInterface;
use Infocyph\Epicrypt\Internal\SecureCompare;

final readonly class StringHasher implements HasherInterface
{
    public function __construct(
        private string $algorithm = 'sha256',
    ) {}

    /**
     * @param array<string, mixed> $options
     */
    public function hash(string $data, array $options = []): string
    {
        $keyOption = $options['key'] ?? '';
        if (!is_string($keyOption)) {
            throw new HashingException('Hash key must be a string.');
        }
        $key = $keyOption;

        $binaryOption = $options['binary'] ?? false;
        if (!is_bool($binaryOption)) {
            throw new HashingException('Binary option must be a boolean.');
        }
        $binary = $binaryOption;

        if ($this->algorithm === 'blake2b') {
            $lengthOption = $options['length'] ?? SODIUM_CRYPTO_GENERICHASH_BYTES;
            if (!is_int($lengthOption)) {
                throw new HashingException('Blake2b length must be an integer.');
            }
            if ($lengthOption < 1) {
                throw new HashingException('Blake2b length must be at least 1.');
            }

            $hash = sodium_crypto_generichash($data, $key, $lengthOption);

            return $binary ? $hash : sodium_bin2hex($hash);
        }

        if (!in_array($this->algorithm, hash_algos(), true)) {
            throw new HashingException('Unsupported hash algorithm: ' . $this->algorithm);
        }

        if ($key === '') {
            $hash = hash($this->algorithm, $data, $binary);
        } else {
            $hash = hash_hmac($this->algorithm, $data, $key, $binary);
        }

        return $hash;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function verify(string $data, string $digest, array $options = []): bool
    {
        return SecureCompare::equals($digest, $this->hash($data, $options));
    }
}
