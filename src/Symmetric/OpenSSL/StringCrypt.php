<?php

namespace Infocyph\Epicrypt\Symmetric\OpenSSL;

use Exception;
use SodiumException;

class StringCrypt
{
    use SSLCommon;

    /**
     * Decrypt a cypher text
     *
     * @param string $encryptedString raw format
     * @return false|string
     * @throws SodiumException
     */
    public function decrypt(string $encryptedString): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'raw');
        $output = $this->decryptionProcess($encryptedString);
        $this->setInfo('bytesRead', mb_strlen($encryptedString, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Decrypt a cypher text
     *
     * @param string $encryptedString base64 encoded format
     * @return false|string
     * @throws SodiumException
     */
    public function decrypt64(string $encryptedString): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'base64');
        if (!$encryptedString = sodium_base642bin($encryptedString, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)) {
            return false;
        }
        $output = $this->decryptionProcess($encryptedString);
        $this->setInfo('bytesRead', mb_strlen($encryptedString, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Decrypt a cypher text
     *
     * @param string $encryptedString hex encoded format
     * @return false|string
     * @throws SodiumException
     */
    public function decryptHex(string $encryptedString): bool|string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'hex');
        $binaryInput = hex2bin($encryptedString);
        if ($binaryInput === false) {
            return false;
        }

        $output = $this->decryptionProcess($binaryInput);
        $this->setInfo('bytesRead', mb_strlen($encryptedString, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
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
     * Encrypt String
     *
     * @return string base64 encoded format
     * @throws SodiumException|Exception
     */
    public function encrypt64(string $input): string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'base64');
        $output = sodium_bin2base64($this->encryptionProcess($input), SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        $this->setInfo('bytesRead', mb_strlen($input, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Encrypt String
     *
     * @return string hex encoded format
     * @throws Exception
     */
    public function encryptHex(string $input): string
    {
        $this->disableSignatureForGcmCcm();
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'hex');
        $output = bin2hex($this->encryptionProcess($input));
        $this->setInfo('bytesRead', mb_strlen($input, '8bit'));
        $this->setInfo('bytesWritten', mb_strlen($output, '8bit'));
        return $output;
    }

    /**
     * Set Tag for GCM/CCM mode
     *
     * @param string $tag Tag for decryption only
     */
    public function setTag(string $tag): void
    {
        $this->tag = $tag;
    }
}
