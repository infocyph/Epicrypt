<?php

namespace AbmmHasan\SafeGuard\Hash;

class GenericStringHash
{
    public function __construct(
        private string $algorithm,
        private string $secret = '',
        private bool   $isBinary = true
    )
    {
    }

    /**
     * @param string $data
     * @return false|string
     */
    public function generate(string $data): bool|string
    {
        if (empty($secret)) {
            return hash($this->algorithm, $data, $this->isBinary);
        }
        return hash_hmac($this->algorithm, $data, $this->secret, $this->isBinary);
    }

    /**
     * @param string $data
     * @param string $hash
     * @return bool
     */
    public function verify(string $data, string $hash): bool
    {
        return hash_equals($hash, $this->generate($data));
    }
}
