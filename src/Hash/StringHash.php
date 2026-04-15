<?php

namespace Infocyph\Epicrypt\Hash;

use SodiumException;

class StringHash
{
    public function __construct(
        private readonly string $algorithm,
        private readonly string $secret = '',
        private readonly bool $isBinary = false,
        private readonly array $options = [],
    ) {}

    /**
     * @param int $hashLength **only available for BLAKE2B Hash
     * @return false|string
     * @throws SodiumException
     */
    public function generate(string $data, int $hashLength = SODIUM_CRYPTO_GENERICHASH_BYTES): bool|string
    {
        return match ($this->algorithm) {
            'sip' => $this->generateHashByAlias('sodium_crypto_shorthash', $data, $this->secret),
            'blake2b' => $this->generateHashByAlias('sodium_crypto_generichash', $data, $this->secret, $hashLength),
            default => match (true) {
                empty($this->secret) => hash($this->algorithm, $data, $this->isBinary, $this->options),
                default => hash_hmac($this->algorithm, $data, $this->secret, $this->isBinary),
            },
        };
    }

    /**
     * @param int $hashLength **only available for BLAKE2B Hash
     * @throws SodiumException
     */
    public function verify(string $data, string $hash, int $hashLength = SODIUM_CRYPTO_GENERICHASH_BYTES): bool
    {
        return hash_equals($hash, $this->generate($data, $hashLength));
    }

    /**
     * @param $function
     * @param ...$params
     * @throws SodiumException
     */
    private function generateHashByAlias($function, ...$params): mixed
    {
        $hash = $function(...$params);
        if ($this->isBinary) {
            return $hash;
        }
        return sodium_bin2hex((string) $hash);
    }
}
