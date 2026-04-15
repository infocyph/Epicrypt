<?php

namespace Infocyph\Epicrypt\DataProtection\OpenSSL;

use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Throwable;

final class InteroperabilityCryptoHelper
{
    private const string CIPHER = 'aes-256-ctr';

    private const string HMAC_ALGORITHM = 'SHA3-512';

    private const string KEY_ALGORITHM = 'SHA3-512';

    private const int KEY_ITERATIONS = 10000;

    private const int KEY_LENGTH = 50;

    private const int SIGNATURE_LENGTH = 64;

    public function decryptString(string $ciphertext, string $secret, string $salt, bool $isBase64 = true): string
    {
        try {
            $rawPayload = $isBase64
                ? sodium_base642bin($ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
                : $ciphertext;

            if ($rawPayload === '') {
                throw new DecryptionException('OpenSSL string payload is invalid.');
            }

            $ivLength = openssl_cipher_iv_length(self::CIPHER);
            if ($ivLength <= 0) {
                throw new DecryptionException('Invalid cipher IV length.');
            }

            if (strlen($rawPayload) < ($ivLength + self::SIGNATURE_LENGTH + 1)) {
                throw new DecryptionException('OpenSSL string payload is too short.');
            }

            $iv = substr($rawPayload, 0, $ivLength);
            $signature = substr($rawPayload, $ivLength, self::SIGNATURE_LENGTH);
            $cipherRaw = substr($rawPayload, $ivLength + self::SIGNATURE_LENGTH);
            $key = $this->deriveKey($secret, $salt);

            $expectedSignature = hash_hmac(self::HMAC_ALGORITHM, $cipherRaw, $key, true);
            if (! hash_equals($expectedSignature, $signature)) {
                throw new DecryptionException('OpenSSL string signature verification failed.');
            }

            $decrypted = openssl_decrypt(
                $cipherRaw,
                self::CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
            );

            if (! is_string($decrypted)) {
                throw new DecryptionException('OpenSSL string decryption failed.');
            }

            return $decrypted;
        } catch (DecryptionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }

    public function encryptString(string $plaintext, string $secret, string $salt, bool $asBase64 = true): string
    {
        try {
            $key = $this->deriveKey($secret, $salt);
            $ivLength = openssl_cipher_iv_length(self::CIPHER);

            if ($ivLength <= 0) {
                throw new EncryptionException('Invalid cipher IV length.');
            }

            $iv = random_bytes($ivLength);
            $cipherRaw = openssl_encrypt(
                $plaintext,
                self::CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
            );

            if (! is_string($cipherRaw)) {
                throw new EncryptionException('OpenSSL string encryption failed.');
            }

            $signature = hash_hmac(self::HMAC_ALGORITHM, $cipherRaw, $key, true);
            $payload = $iv . $signature . $cipherRaw;

            if (! $asBase64) {
                return $payload;
            }

            return sodium_bin2base64($payload, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        } catch (Throwable $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    private function deriveKey(string $secret, string $salt): string
    {
        $key = openssl_pbkdf2(
            $secret,
            $salt,
            self::KEY_LENGTH,
            self::KEY_ITERATIONS,
            self::KEY_ALGORITHM,
        );

        if (! is_string($key) || $key === '') {
            throw new \RuntimeException('Unable to derive OpenSSL encryption key.');
        }

        return $key;
    }
}
