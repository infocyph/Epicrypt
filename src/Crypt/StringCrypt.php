<?php


namespace AbmmHasan\SafeGuard\Crypt;


use Exception;

class StringCrypt
{
    private string $secret = '';
    private string $salt = '';
    private string $iv = '';

    private int $keyIterationCount = 10000;
    private int $keyLength = 50;
    private string $keyAlgo = 'SHA3-512';
    private bool $isIVPredefined = false;

    private bool $enableSignature = true;
    private string $hmacAlgo = 'SHA3-512';
    private int $sha2Len = 64;

    private string $encryptionMethod = 'aes-256-cbc';

    private array $info;
    private string $tag;

    /**
     * Constructor: Set Secret & Salt (& optionally IV string) for encryption/decryption
     *
     * @param string $secret Secret string to encrypt with
     * @param string $salt Salt string for hashing
     * @param string $iv IV string (if omitted IV will be generated automatically)
     * @param string $tag Tag for GCM/CCM type decryption only
     */
    public function __construct(string $secret, string $salt, string $iv = '', string $tag = '')
    {
        $this->secret = $secret;
        $this->salt = $salt;
        $this->iv = $iv;
        $this->tag = $tag;
        if (!empty($iv)) {
            $this->isIVPredefined = true;
        }
    }

    /**
     * Get the method details
     *
     * @param null $key
     * @return mixed
     */
    public function getInfo($key = null): mixed
    {
        return is_null($key) ? $this->info : ($this->info[$key] ?? null);
    }

    /**
     * Set info
     *
     * @param $key
     * @param $value
     * @return mixed
     */
    protected function setInfo($key, $value): mixed
    {
        return $this->info[$key] = $value;
    }

    /**
     * Disable Signature
     */
    public function disableSignature()
    {
        $this->enableSignature = false;
    }

    /**
     * Return set IV
     *
     * Can be called after IV is set (if automatic generation then after encryption)
     *
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * Set encryption method
     *
     * Default: AES-256-CBC
     *
     * @param string $method
     */
    public function setEncryptionMethod(string $method)
    {
        $this->encryptionMethod = $method;
    }

    /**
     * Set Encryption key property
     *
     * Default: Algorithm: SHA3-512, Length: 50, Iteration Count: 10000
     *
     * @param string $algorithm
     * @param int $length
     * @param int $iterationCount
     */
    public function setKeyProperty(string $algorithm, int $length, int $iterationCount)
    {
        $this->keyAlgo = $algorithm;
        $this->keyLength = $length;
        $this->keyIterationCount = $iterationCount;
    }

    /**
     * Set property for signature key, used for signing/verifying encryption
     *
     * @param string $algorithm
     * @param int $length
     */
    public function setSignatureProperty(string $algorithm, int $length)
    {
        $this->hmacAlgo = $algorithm;
        $this->sha2Len = $length;
    }

    /**
     * Generate encryption key
     *
     * @return false|string
     */
    private function getKey(): bool|string
    {
        if (stripos($this->encryptionMethod, '-gcm') || stripos($this->encryptionMethod, '-ccm')) {
            $this->enableSignature = false;
        }
        return openssl_pbkdf2(
            $this->secret,
            $this->salt,
            $this->setInfo('keyLength', $this->keyLength),
            $this->setInfo('keyIterationCount', $this->keyIterationCount),
            $this->setInfo('keyAlgo', $this->keyAlgo)
        );
    }

    /**
     * Calculate/Generate IV string
     *
     * @throws Exception
     */
    private function calculateIV()
    {
        $length = openssl_cipher_iv_length($this->encryptionMethod);
        if (!empty($this->iv) && ($found = mb_strlen($this->iv, '8bit')) != $length) {
            throw new Exception("IV length mismatch (Expected: {$length}B, Found: {$found}B)");
        }
        if (empty($this->iv) && $length > 0) {
            $this->iv = openssl_random_pseudo_bytes($length);
        }
        $this->setInfo('predefinedIV', $this->isIVPredefined);
    }

    /**
     * Encrypt content
     *
     * @param string $input String for encrypt
     * @return string raw format
     * @throws Exception
     */
    protected function encryptionProcess(string $input): string
    {
        self::calculateIV();
        $encryptionKey = self::getKey();
        $cText = openssl_encrypt(
            $input,
            $this->setInfo('encryptionMethod', $this->encryptionMethod),
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->info['tag']
        );
        if ($this->setInfo('enableSignature', $this->enableSignature) === true) {
            $cText = hash_hmac(
                    $this->setInfo('hmacAlgo', $this->hmacAlgo), $cText, $encryptionKey, true
                ) . $cText;
        }
        if ($this->isIVPredefined === false) {
            $cText = $this->iv . $cText;
        }
        return $cText;
    }

    /**
     * Decrypt cypher content
     *
     * @param string $input raw format
     * @return false|string
     */
    protected function decryptionProcess(string $input): bool|string
    {
        $ivLen = openssl_cipher_iv_length($this->encryptionMethod);
        $cTextOffset = 0;
        $encryptionKey = self::getKey();
        if ($definedIV = ($this->setInfo('predefinedIV', $this->isIVPredefined) === false)) {
            $this->iv = substr($input, 0, $ivLen);
            $cTextOffset += $ivLen;
        }
        if ($this->setInfo('enableSignature', $this->enableSignature) === true) {
            $cTextOffset += $this->sha2Len;
            $hash = substr(
                $input,
                $definedIV ? $ivLen : 0,
                $this->sha2Len
            );
        }
        $cText = substr($input, $cTextOffset);

        if ($this->enableSignature === true && !empty($hash) &&
            !hash_equals($hash, hash_hmac($this->setInfo('hmacAlgo', $this->hmacAlgo), $cText, $encryptionKey, true))) {
            return false;
        }

        return openssl_decrypt(
            $cText,
            $this->setInfo('encryptionMethod', $this->encryptionMethod),
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->tag
        );
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
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'hex');
        return self::decryptionProcess(hex2bin($encryptedString));
    }
}
