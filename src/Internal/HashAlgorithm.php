<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

/**
 * @internal
 */
final class HashAlgorithm
{
    /**
     * @var list<string>|null
     */
    private static ?array $supported = null;

    public static function assertSupported(string $algorithm): void
    {
        if (!self::isSupported($algorithm)) {
            throw new \InvalidArgumentException('Unsupported hash algorithm: ' . $algorithm);
        }
    }

    public static function isSupported(string $algorithm): bool
    {
        return in_array($algorithm, self::$supported ??= hash_algos(), true);
    }
}
