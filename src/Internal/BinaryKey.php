<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

/**
 * @internal
 */
final class BinaryKey
{
    public static function aeadKey(mixed $value, bool $isBinary, int $expectedLength, string $name = 'AEAD key'): string
    {
        return self::decodeFixedLength($value, $isBinary, $expectedLength, $name);
    }

    public static function boxKeypair(mixed $value, bool $isBinary, string $name = 'Box keypair'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_BOX_KEYPAIRBYTES, $name);
    }

    public static function boxPublicKey(mixed $value, bool $isBinary, string $name = 'Box public key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, $name);
    }

    public static function boxSecretKey(mixed $value, bool $isBinary, string $name = 'Box secret key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, $name);
    }

    public static function decodeBase64UrlOrBinary(mixed $value, bool $isBinary, string $name = 'Key'): string
    {
        if (!is_string($value) || $value === '') {
            throw new InvalidKeyException(sprintf('%s must be a non-empty string.', $name));
        }

        if ($isBinary) {
            return $value;
        }

        try {
            return Base64Url::decode($value);
        } catch (ConfigurationException $e) {
            throw new InvalidKeyException(sprintf('%s must be valid base64url data.', $name), 0, $e);
        }
    }

    public static function macKey(mixed $value, bool $isBinary, string $name = 'MAC key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_AUTH_KEYBYTES, $name);
    }

    public static function secretBoxKey(mixed $value, bool $isBinary, string $name = 'Secret-box key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $name);
    }

    public static function secretStreamKey(mixed $value, bool $isBinary, string $name = 'Secret-stream key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, $name);
    }

    public static function signPublicKey(mixed $value, bool $isBinary, string $name = 'Sign public key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, $name);
    }

    public static function signSecretKey(mixed $value, bool $isBinary, string $name = 'Sign secret key'): string
    {
        return self::decodeFixedLength($value, $isBinary, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, $name);
    }

    private static function decodeFixedLength(mixed $value, bool $isBinary, int $expectedLength, string $name): string
    {
        if ($expectedLength < 1) {
            throw new InvalidKeyException(sprintf('%s expected length must be greater than zero.', $name));
        }

        $decoded = self::decodeBase64UrlOrBinary($value, $isBinary, $name);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s must be %d bytes.', $name, $expectedLength));
        }

        return $decoded;
    }
}
