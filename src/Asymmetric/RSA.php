<?php


namespace AbmmHasan\SafeGuard\Asymmetric;


use Exception;
use OpenSSLAsymmetricKey;

class RSA
{
    public function __construct(
        private bool $binary = true,
        private int $padding = OPENSSL_PKCS1_OAEP_PADDING
    )
    {
    }

    /**
     * @param string $data
     * @param $publicKeyResource
     * @return string
     * @throws Exception
     */
    public function encrypt(string $data, $publicKeyResource): string
    {
        if (empty($data)) {
            throw new Exception('Invalid Input data!');
        }
        $publicKeyResource = $this->processKeyResource('public', $publicKeyResource);
        if (false === openssl_public_encrypt(
                $data,
                $encrypted,
                $publicKeyResource,
                $this->padding
            )) {
            throw new Exception('Encryption failed; ' . $this->getSSLError());
        }

        if ($this->binary) {
            return $encrypted;
        }
        return base64_encode($encrypted);
    }

    /**
     * @param string $data
     * @param $privateKeyResource
     * @param null $passphrase
     * @return string
     * @throws Exception
     */
    public function decrypt(string $data, $privateKeyResource, $passphrase = null): string
    {
        if (!$this->binary) {
            $data = base64_decode($data);
        }
        if (empty($data)) {
            throw new Exception('Invalid Input data!');
        }
        $privateKeyResource = $this->processKeyResource('private', $privateKeyResource, $passphrase);
        if (false === openssl_private_decrypt(
                $data,
                $decrypted,
                $privateKeyResource,
                $this->padding
            )) {
            throw new Exception('Decryption failed; ' . $this->getSSLError());
        }
        return $decrypted;
    }

    /**
     * @param $type
     * @param $resource
     * @param null $passphrase
     * @return OpenSSLAsymmetricKey
     * @throws Exception
     */
    private function processKeyResource($type, $resource, $passphrase = null): OpenSSLAsymmetricKey
    {
        if (is_file($resource)) {
            if (!is_readable($resource)) {
                throw new Exception("Unreadable file $resource!");
            }
            $content = file_get_contents($resource);
        } elseif (is_string($resource)) {
            $content = $resource;
        } else {
            throw new Exception("Invalid key resource!");
        }

        if ($type === 'public') {
            $result = openssl_pkey_get_public($content);
        } else {
            $result = openssl_pkey_get_private($content, $passphrase);
        }
        if (false === $result) {
            throw new Exception('Unable to load key; ' . $this->getSSLError());
        }
        return $result;
    }

    /**
     * @return false|string
     */
    private function getSSLError(): bool|string
    {
        if (($e = openssl_error_string()) !== false) {
            return $e;
        }
    }
}
