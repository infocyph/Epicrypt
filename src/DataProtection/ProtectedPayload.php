<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Throwable;

/** @internal */
final class ProtectedPayload
{
    public const string PREFIX = 'ep2';

    private const int VERSION = 2;

    public static function decrypt(
        string $payload,
        #[\SensitiveParameter]
        string $key,
        string $expectedDomain,
        ProtectionOptions $options,
        ProtectionAlgorithm $algorithm,
    ): ProtectionResult {
        self::assertKey($key, $algorithm);

        try {
            $parts = explode('.', $payload);
            if (count($parts) !== 4 || $parts[0] !== self::PREFIX) {
                throw new DecryptionException('Invalid Epicrypt 2.0 protected payload framing.');
            }

            [, $encodedHeader, $encodedNonce, $encodedCiphertext] = $parts;
            $header = self::decodeHeader($encodedHeader, $expectedDomain, $options, $algorithm);
            $nonce = Base64Url::decode($encodedNonce);
            if (strlen($nonce) !== $algorithm->nonceLength()) {
                throw new DecryptionException('Invalid Epicrypt 2.0 payload nonce.');
            }

            $plaintext = self::runRawOperation(
                Base64Url::decode($encodedCiphertext),
                self::PREFIX . '.' . $encodedHeader,
                $nonce,
                $key,
                $algorithm,
                true,
            );
            if ($plaintext === false) {
                throw new DecryptionException('Epicrypt 2.0 payload authentication failed.');
            }

            return new ProtectionResult(
                value: $plaintext,
                domain: $expectedDomain,
                purpose: $header['purpose'],
                createdAt: $header['created_at'],
                keyId: $header['kid'],
            );
        } catch (DecryptionException|InvalidKeyException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new DecryptionException('Invalid Epicrypt 2.0 protected payload.', 0, $exception);
        }
    }

    public static function encrypt(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        string $domain,
        ProtectionOptions $options,
        int $createdAt,
        ProtectionAlgorithm $algorithm,
    ): ProtectionResult {
        self::assertKey($key, $algorithm);

        $header = [
            'v' => self::VERSION,
            'domain' => $domain,
            'alg' => $algorithm->value,
            'kid' => $options->keyId,
            'purpose' => $options->purpose,
            'created_at' => $createdAt,
            'aad' => Base64Url::encode($options->additionalAuthenticatedData),
        ];
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $nonce = random_bytes($algorithm->nonceLength());
        $ciphertext = self::runRawOperation(
            $plaintext,
            self::PREFIX . '.' . $encodedHeader,
            $nonce,
            $key,
            $algorithm,
            false,
        );
        if (!is_string($ciphertext)) {
            throw new EncryptionException('Epicrypt 2.0 payload encryption failed.');
        }

        return new ProtectionResult(
            value: implode('.', [
                self::PREFIX,
                $encodedHeader,
                Base64Url::encode($nonce),
                Base64Url::encode($ciphertext),
            ]),
            domain: $domain,
            purpose: $options->purpose,
            createdAt: $createdAt,
            keyId: $options->keyId,
        );
    }

    public static function keyId(
        string $payload,
        string $expectedDomain,
        ProtectionOptions $options,
        ProtectionAlgorithm $algorithm,
    ): ?string {
        $parts = explode('.', $payload);
        if (count($parts) !== 4 || $parts[0] !== self::PREFIX) {
            throw new DecryptionException('Invalid Epicrypt 2.0 protected payload framing.');
        }

        return self::decodeHeader($parts[1], $expectedDomain, $options, $algorithm)['kid'];
    }

    private static function assertKey(string $key, ProtectionAlgorithm $algorithm): void
    {
        if (strlen($key) !== $algorithm->keyLength()) {
            throw new InvalidKeyException(sprintf(
                'Protection key must be %d bytes.',
                $algorithm->keyLength(),
            ));
        }
    }

    /**
     * @return array{v: int, domain: string, alg: string, kid: ?string, purpose: string, created_at: int, aad: string}
     */
    private static function decodeHeader(
        string $encodedHeader,
        string $expectedDomain,
        ProtectionOptions $options,
        ProtectionAlgorithm $algorithm,
    ): array {
        $header = Json::decodeToArray(Base64Url::decode($encodedHeader));
        $expectedKeys = ['aad', 'alg', 'created_at', 'domain', 'kid', 'purpose', 'v'];
        $keys = array_keys($header);
        sort($keys);
        if ($keys !== $expectedKeys) {
            throw new DecryptionException('Invalid Epicrypt 2.0 authenticated header fields.');
        }

        if ($header['v'] !== self::VERSION
            || $header['domain'] !== $expectedDomain
            || $header['alg'] !== $algorithm->value
            || $header['purpose'] !== $options->purpose
            || $header['aad'] !== Base64Url::encode($options->additionalAuthenticatedData)
            || !is_int($header['created_at'])
            || ($header['kid'] !== null
                && (!is_string($header['kid']) || preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $header['kid']) !== 1))
            || ($options->keyId !== null && $header['kid'] !== $options->keyId)) {
            throw new DecryptionException('Epicrypt 2.0 authenticated metadata does not match the operation.');
        }

        return [
            'v' => self::VERSION,
            'domain' => $expectedDomain,
            'alg' => $algorithm->value,
            'kid' => $header['kid'],
            'purpose' => $options->purpose,
            'created_at' => $header['created_at'],
            'aad' => Base64Url::encode($options->additionalAuthenticatedData),
        ];
    }

    private static function runRawOperation(
        string $input,
        string $aad,
        string $nonce,
        string $key,
        ProtectionAlgorithm $algorithm,
        bool $decrypt,
    ): string|false {
        return match ($algorithm) {
            ProtectionAlgorithm::AES_256_GCM => $decrypt
                ? sodium_crypto_aead_aes256gcm_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_aes256gcm_encrypt($input, $aad, $nonce, $key),
            ProtectionAlgorithm::XCHACHA20_POLY1305 => $decrypt
                ? sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($input, $aad, $nonce, $key)
                : sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($input, $aad, $nonce, $key),
        };
    }
}
