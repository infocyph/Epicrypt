<?php

namespace Infocyph\Epicrypt\Internal;

final class VersionedPayload
{
    public static function encode(string $version, string ...$parts): string
    {
        return implode('.', array_merge([$version], $parts));
    }

    /**
     * @return array{bool, array<int, string>}|null
     */
    public static function parse(string $payload, string $expectedVersion, int $partCount): ?array
    {
        $segments = explode('.', $payload);

        if (count($segments) === ($partCount + 1) && $segments[0] === $expectedVersion) {
            $versionedParts = array_slice($segments, 1);
            if (self::allNonEmpty($versionedParts)) {
                return [true, $versionedParts];
            }
        }

        if (count($segments) === $partCount && self::allNonEmpty($segments)) {
            return [false, $segments];
        }

        return null;
    }

    /**
     * @param array<int, string> $segments
     */
    private static function allNonEmpty(array $segments): bool
    {
        return array_all($segments, fn($segment) => !($segment === ''));
    }
}
