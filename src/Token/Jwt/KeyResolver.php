<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use ArrayAccess;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;

final class KeyResolver
{
    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public static function resolve(string|array|ArrayAccess $key, mixed $keyId = null): string
    {
        if (is_string($key)) {
            self::validateStringKey($key);

            return $key;
        }

        $kid = self::requireKeyId($keyId);
        $resolved = self::resolveFromKeyset($key, $kid);
        if (!is_string($resolved) || $resolved === '') {
            throw new KeyResolutionException('Resolved key must be a non-empty string.');
        }

        return $resolved;
    }

    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public static function validate(string|array|ArrayAccess $key, mixed $keyId = null): void
    {
        if (is_string($key)) {
            self::validateStringKey($key);

            return;
        }

        $kid = self::requireKeyId($keyId);
        $resolved = self::resolveFromKeyset($key, $kid);
        self::validateResolved($resolved);
    }

    private static function requireKeyId(mixed $keyId): string
    {
        if (!is_string($keyId) || $keyId === '') {
            throw new KeyResolutionException('"kid" is required when using key-set mode.');
        }

        return $keyId;
    }

    /**
     * @param array<string, mixed>|ArrayAccess<string, mixed> $keyset
     */
    private static function resolveFromKeyset(array|ArrayAccess $keyset, string $keyId): mixed
    {
        if (is_array($keyset)) {
            if (!array_key_exists($keyId, $keyset)) {
                throw new KeyResolutionException('"kid" invalid, lookup failed.');
            }

            return $keyset[$keyId];
        }

        if (!$keyset->offsetExists($keyId)) {
            throw new KeyResolutionException('"kid" invalid, lookup failed.');
        }

        return $keyset[$keyId];
    }

    private static function validateResolved(mixed $resolved): void
    {
        if (!is_string($resolved) || $resolved === '') {
            throw new KeyResolutionException('Resolved key must be a non-empty string.');
        }
    }

    private static function validateStringKey(string $key): void
    {
        if ($key === '') {
            throw new KeyResolutionException('Signing key must be a non-empty string.');
        }
    }
}
