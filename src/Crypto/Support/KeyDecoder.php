<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Support;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyDecoder
{
    /**
     * @return non-empty-string
     */
    public static function decode(mixed $value, bool $isBinary, int $expectedLength, string $name): string
    {
        if ($expectedLength < 1) {
            throw new InvalidKeyException(sprintf('%s expected length must be greater than zero.', $name));
        }

        if (!is_string($value) || $value === '') {
            throw new InvalidKeyException(sprintf('%s must be a non-empty string.', $name));
        }

        $decoded = $isBinary ? $value : Base64Url::decode($value);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s has invalid length.', $name));
        }

        return $decoded;
    }
}
