<?php


namespace AbmmHasan\SafeGuard\Asymmetric;


use OpenSSLAsymmetricKey;

class DiffieHellman
{
    private false|OpenSSLAsymmetricKey $resource;

    /**
     * Set the prime, generator & private key
     *
     * @param string $prime prime number (shared)
     * @param string $generator generator (shared)
     * @param string $privateKey user private key
     */
    public function __construct(
        string $prime,
        string $generator,
        string $privateKey
    )
    {
        $this->resource = openssl_pkey_new([
            'dh' => [
                'p' => $prime,
                'g' => $generator,
                'priv_key' => $privateKey
            ],
            'private_key_type' => OPENSSL_KEYTYPE_DH
        ]);
    }

    /**
     * Get user public key
     *
     * @param bool $encoded
     * @return string
     */
    public function getPublicKey(bool $encoded = true): mixed
    {
        $keyResource = openssl_pkey_get_details($this->resource);
        return $encoded ? $keyResource['key'] : $keyResource['dh']['pub_key'];
    }

    /**
     * Get computed secret key
     *
     * @param $publicKey string public key resource
     * @param bool $encoded
     * @return false|string
     */
    public function computeSecretKey(string $publicKey, bool $encoded = true): bool|string
    {
        if ($encoded) {
            $publicKey = openssl_pkey_get_details(
                openssl_pkey_get_public($publicKey)
            )['dh']['pub_key'];
        }
        return openssl_dh_compute_key($publicKey, $this->resource);
    }
}
