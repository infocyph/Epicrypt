<?php


namespace AbmmHasan\SafeGuard\Symmetric;


use Exception;

trait Common
{
    private int $keyIterationCount = 10000;
    private int $keyLength = 50;
    private string $keyAlgo = 'SHA3-512';
    private bool $isIVPredefined = false;

    private bool $enableSignature = true;
    private string $hmacAlgo = 'SHA3-512';
    private int $sha2Len = 64;

    private string $encryptionMethod = 'aes-256-ctr';

    private string $aad = '';
    private string $tag = '';

    private array $info;

    /**
     * Constructor: Set Secret & Salt (& optionally IV string) for encryption/decryption
     *
     * @param string $secret Secret string to encrypt with
     * @param string $salt Salt string for hashing
     * @param string $iv IV string (if omitted IV will be generated automatically)
     */
    public function __construct(
        private string $secret,
        private string $salt,
        private string $iv = '')
    {
        if (!empty($iv)) {
            $this->isIVPredefined = true;
        }
    }

    /**
     * Set Additional Authentication Data for GCM/CCM mode
     *
     * @param string $aad Additional Auth Info for both Encrypt/Decrypt
     */
    public function setAad(string $aad)
    {
        $this->aad = $aad;
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
    private function setInfo($key, $value): mixed
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
     * @param string $method
     */
    public function setEncryptionMethod(string $method = 'aes-256-ctr')
    {
        $this->encryptionMethod = $method;
    }

    /**
     * Set Encryption key property
     *
     * @param string $algorithm
     * @param int $length
     * @param int $iterationCount
     */
    public function setKeyProperty(string $algorithm = 'SHA3-512', int $length = 50, int $iterationCount = 10000)
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
    public function setSignatureProperty(string $algorithm = 'SHA3-512', int $length = 64)
    {
        $this->hmacAlgo = $algorithm;
        $this->sha2Len = $length;
    }

    /**
     * Disable Signature in case of GCM/CCM mode
     */
    private function disableSignatureForGcmCcm()
    {
        if (stripos($this->encryptionMethod, '-gcm') || stripos($this->encryptionMethod, '-ccm')) {
            $this->disableSignature();
        }
    }

    /**
     * Generate encryption key
     *
     * @return false|string
     */
    private function getKey(): bool|string
    {
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
    private function encryptionProcess(string $input): string
    {
        self::calculateIV();
        $encryptionKey = self::getKey();
        $cText = openssl_encrypt(
            $input,
            $this->setInfo('encryptionMethod', $this->encryptionMethod),
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $this->iv,
            $generatedTag,
            $this->aad
        );
        $this->info['tag'][] = base64_encode($generatedTag);
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
    private function decryptionProcess(string $input): bool|string
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
            base64_decode($this->tag),
            $this->aad
        );
    }

}
