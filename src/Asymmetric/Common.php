<?php

namespace AbmmHasan\SafeGuard\Asymmetric;

use Exception;

trait Common
{
    /**
     * @param $resource
     * @return mixed
     * @throws Exception
     */
    private function prepareInput($resource): mixed
    {
        if (is_file($resource)) {
            if (!is_readable($resource)) {
                throw new Exception("Unreadable file $resource!");
            }
            return file_get_contents($resource);
        }
        return $resource;
    }

    /**
     * @param $result
     * @param bool $isRSA
     * @throws Exception
     */
    private function check($result, bool $isRSA = false)
    {
        if (false === $result) {
            throw new Exception('Unable to load key; ' . $this->getSSLError());
        }

        if ($isRSA && !isset(openssl_pkey_get_details($result)['rsa'])) {
            throw new Exception('Only RSA is supported!');
        }
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
