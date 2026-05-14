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

    public static function fixedLength(mixed $value, bool $isBinary, int $expectedLength, string $name = 'Key'): string
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
