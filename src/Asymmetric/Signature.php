<?php


namespace AbmmHasan\SafeGuard\Asymmetric;


use Exception;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

class Signature
{
    use Common;

    /**
     * Constructor: Predefined parameters
     *
     * @param bool $isBinary Set signature type
     * @param int|string $signatureAlgo
     */
    public function __construct(
        private bool $isBinary = true,
        private int|string $signatureAlgo = OPENSSL_ALGO_SHA512
    )
    {
    }

    /**
     * Sign data using Private key
     *
     * @param string $data Data to sign
     * @param OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key Private key resource
     * @param string|null $passphrase (optional) Password used for private key encryption
     * @return string Signature
     * @throws Exception
     */
    public function Sign(string $data, OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key, string $passphrase = null): string
    {
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);
        $key = openssl_pkey_get_private($key, $passphrase);
        $this->check($key);
        if (false === openssl_sign(
                $data,
                $signature,
                $key,
                $this->signatureAlgo
            )) {
            throw new Exception('Unable to generate signature; ' . $this->getSSLError());
        }

        if ($this->isBinary) {
            return $signature;
        }
        return base64_encode($signature);
    }

    /**
     * Verify signature using Public key
     *
     * @param string $data Signed data
     * @param OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key Public key resource
     * @param string $signature Signature to verify with
     * @return bool Verified or Not
     * @throws Exception
     */
    public function verify(string $data, OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key, string $signature): bool
    {
        if (!$this->isBinary) {
            $data = base64_decode($data, true);
        }
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);
        $key = openssl_pkey_get_public($key);
        $this->check($key);
        $result = openssl_verify(
            $data,
            $signature,
            $key,
            $this->signatureAlgo
        );
        if (-1 === $result || false === $result) {
            throw new Exception('Signature verification failed; ' . $this->getSSLError());
        }
        return $result === 1;
    }
}
