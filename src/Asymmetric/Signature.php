<?php


namespace AbmmHasan\SafeGuard\Asymmetric;


use AbmmHasan\SafeGuard\Asymmetric\OpenSSL\Common;
use Exception;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use SodiumException;

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
    ) {
    }

    /**
     * Sign data using Private key
     *
     * @param string $data Data to sign
     * @param OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key Private key resource
     * @param string|null $passphrase (optional) Password used for OpenSSl private key encryption
     * @return string Signature
     * @throws Exception|SodiumException
     */
    public function sign(
        string $data,
        OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key,
        string $passphrase = null
    ): string {
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);

        if ($this->signatureAlgo === 'sodium_detached') {
            $signature = sodium_crypto_sign_detached($data, $key);
        } else {
            $signature = $this->openSSLSign($key, $data, $passphrase);
        }

        if ($this->isBinary) {
            return $signature;
        }

        return sodium_bin2base64($signature, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
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
    public function verify(
        string $data,
        OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key,
        string $signature
    ): bool {
        if (!$this->isBinary) {
            $signature = sodium_base642bin($signature, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);

        if ($this->signatureAlgo === 'sodium_detached') {
            return sodium_crypto_sign_verify_detached($signature, $data, $key);
        } else {
            return $this->openSSLVerify($key, $data, $signature);
        }
    }

    /**
     * Verify Signature with OpenSSL
     *
     * @param $key
     * @param $data
     * @param $signature
     * @return bool
     * @throws Exception
     */
    private function openSSLVerify($key, $data, $signature): bool
    {
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

    /**
     * Sign using OpenSSL
     *
     * @param $key
     * @param $data
     * @param $passphrase
     * @return mixed
     * @throws Exception
     */
    private function openSSLSign($key, $data, $passphrase): mixed
    {
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
        return $signature;
    }
}
