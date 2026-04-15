<?php

namespace Infocyph\Epicrypt\Token\JWT;

use ArrayAccess;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;

final class KeyResolver
{
    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public static function resolve(string|array|ArrayAccess $key, mixed $keyId = null): string
    {
        self::validate($key, $keyId);

        if (is_string($key)) {
            return $key;
        }

        $resolved = $key[$keyId];

        return (string) $resolved;
    }
    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public static function validate(string|array|ArrayAccess $key, mixed $keyId = null): void
    {
        if (is_string($key)) {
            if ($key === '') {
                throw new KeyResolutionException('Signing key must be a non-empty string.');
            }

            return;
        }

        if ($keyId === null) {
            throw new KeyResolutionException('"kid" is required when using key-set mode.');
        }

        if (! isset($key[$keyId])) {
            throw new KeyResolutionException('"kid" invalid, lookup failed.');
        }

        $resolved = $key[$keyId];
        if (! is_string($resolved) || $resolved === '') {
            throw new KeyResolutionException('Resolved key must be a non-empty string.');
        }
    }
}
