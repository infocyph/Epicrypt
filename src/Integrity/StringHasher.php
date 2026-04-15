<?php

namespace Infocyph\Epicrypt\Integrity;

use Infocyph\Epicrypt\Contract\HasherInterface;
use Infocyph\Epicrypt\Exception\Integrity\HashingException;
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
        $key = $options['key'] ?? '';
        $binary = (bool) ($options['binary'] ?? false);

        if ($this->algorithm === 'blake2b') {
            $length = (int) ($options['length'] ?? SODIUM_CRYPTO_GENERICHASH_BYTES);
            $hash = sodium_crypto_generichash($data, (string) $key, $length);

            return $binary ? $hash : sodium_bin2hex($hash);
        }

        if (! in_array($this->algorithm, hash_algos(), true)) {
            throw new HashingException('Unsupported hash algorithm: ' . $this->algorithm);
        }

        if ($key === '') {
            $hash = hash($this->algorithm, $data, $binary);
        } else {
            $hash = hash_hmac($this->algorithm, $data, (string) $key, $binary);
        }

        if (! is_string($hash)) {
            throw new HashingException('Hash generation failed.');
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
