<?php


namespace AbmmHasan\SafeGuard\Symmetric;


use Exception;

class StringCrypt
{
    use Common;

    /**
     * Set Tag for GCM/CCM mode
     *
     * @param string $tag Tag for decryption only
     */
    public function setTag(string $tag)
    {
        $this->tag = $tag;
    }

    /**
     * Encrypt a string
     *
     * @param string $input String for encrypt
     * @return string raw format
     * @throws Exception
     */
    public function encrypt(string $input): string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'raw');
        $output = $this->encryptionProcess($input);
        $this->setInfo('bytesRead', mb_strlen($input, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Decrypt a cypher text
     *
     * @param string $input raw format
     * @return false|string
     */
    public function decrypt(string $input): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'raw');
        $output = $this->decryptionProcess($input);
        $this->setInfo('bytesRead', mb_strlen($input, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Encrypt String
     *
     * @param string $string
     * @return string base64 encoded format
     * @throws Exception
     */
    public function encrypt64(string $string): string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'base64');
        return trim(base64_encode(self::encryptionProcess($string)), '=');
    }

    /**
     * Decrypt a cypher text
     *
     * @param string $encryptedString base64 encoded format
     * @return false|string
     */
    public function decrypt64(string $encryptedString): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'base64');
        if (!$encryptedString = base64_decode($encryptedString, true)) {
            return false;
        }
        return self::decryptionProcess($encryptedString);
    }

    /**
     * Encrypt String
     *
     * @param string $string
     * @return string hex encoded format
     * @throws Exception
     */
    public function encryptHex(string $string): string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'hex');
        return bin2hex(self::encryptionProcess($string));
    }

    /**
     * Decrypt a cypher text
     *
     * @param string $encryptedString hex encoded format
     * @return false|string
     */
    public function decryptHex(string $encryptedString): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'hex');
        return self::decryptionProcess(hex2bin($encryptedString));
    }
}