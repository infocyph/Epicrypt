<?php


namespace AbmmHasan\SafeGuard\Asymmetric\OpenSSL;


use AbmmHasan\SafeGuard\Asymmetric\Common;
use Exception;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

class RSA
{
    use Common;

    /**
     * Constructor: Predefined parameters
     *
     * @param bool $isBinary Set, Encryption return type / Decryption input type
     * @param int $padding OpenSSL padding type
     */
    public function __construct(
        private bool $isBinary = true,
        private int $padding = OPENSSL_PKCS1_OAEP_PADDING
    ) {
    }

    /**
     * Encrypt data using RSA (public key)
     *
     * @param string $data Data to encrypt
     * @param OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key Public key resource
     * @return string Encrypted data
     * @throws Exception
     */
    public function encrypt(string $data, OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key): string
    {
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);
        $key = openssl_pkey_get_public($key);
        $this->check($key, true);
        if (false === openssl_public_encrypt(
                $data,
                $encrypted,
                $key,
                $this->padding
            )) {
            throw new Exception('Encryption failed; ' . $this->getSSLError());
        }

        if ($this->isBinary) {
            return $encrypted;
        }
        return sodium_bin2base64($encrypted, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Decrypt encrypted data using RSA (private key)
     *
     * @param string $data Encrypted data
     * @param OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key Private key resource
     * @param string|null $passphrase (optional) Password used for private key encryption
     * @return string Decrypted data
     * @throws Exception
     */
    public function decrypt(
        string $data,
        OpenSSLAsymmetricKey|array|string|OpenSSLCertificate $key,
        string $passphrase = null
    ): string {
        if (!$this->isBinary) {
            $data = sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }
        if (empty($data)) {
            throw new Exception('Invalid input data!');
        }
        $key = $this->prepareInput($key);
        $key = openssl_pkey_get_private($key, $passphrase);
        $this->check($key, true);
        if (false === openssl_private_decrypt(
                $data,
                $decrypted,
                $key,
                $this->padding
            )) {
            throw new Exception('Decryption failed; ' . $this->getSSLError());
        }
        return $decrypted;
    }
}
