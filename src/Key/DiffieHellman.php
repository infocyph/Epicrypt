<?php


namespace AbmmHasan\SafeGuard\Key;


use OpenSSLAsymmetricKey;

class DiffieHellman
{
    private false|OpenSSLAsymmetricKey $resource;

    /**
     * Set the prime, generator & private key
     *
     * @param string $prime prime number
     * @param string $generator generator
     * @param string $privateKey user private key
     */
    public function __construct(
        private string $prime,
        private string $generator,
        private string $privateKey
    )
    {
        $this->resource = openssl_pkey_new([
            'dh' => [
                'p' => $this->prime,
                'g' => $this->generator,
                'priv_key' => $this->privateKey
            ],
            'private_key_type' => OPENSSL_KEYTYPE_DH
        ]);
    }

    /**
     * Get user public key
     *
     * @return mixed
     */
    public function getPublicKey(): mixed
    {
        return openssl_pkey_get_details($this->resource)['key'] ?? false;
    }

    /**
     * Get computed secret key
     *
     * @param $publicKey
     * @return false|string
     */
    public function computeSecretKey($publicKey): bool|string
    {
        return openssl_dh_compute_key(
            openssl_pkey_get_details(
                openssl_pkey_get_public($publicKey)
            )['dh']['pub_key'], $this->resource
        );
    }
}
