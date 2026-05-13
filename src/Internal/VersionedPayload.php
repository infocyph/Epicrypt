<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

final class VersionedPayload
{
    public const string EMPTY_KEY_ID = '_';

    public static function encode(string $version, string ...$parts): string
    {
        return implode('.', array_merge([$version], $parts));
    }

    public static function encodeCompact(string $version, string $algorithm, ?string $keyId, string $nonce, string $ciphertext): string
    {
        if ($algorithm === '' || str_contains($algorithm, '.')) {
            throw new \InvalidArgumentException('Payload algorithm must be a non-empty dot-safe string.');
        }

        if ($nonce === '' || $ciphertext === '') {
            throw new \InvalidArgumentException('Payload nonce and ciphertext must be non-empty strings.');
        }

        return self::encode(
            $version,
            $algorithm,
            self::normalizeKeyIdForEncoding($keyId),
            $nonce,
            $ciphertext,
        );
    }

    public static function parse(string $payload, string $expectedVersion, int $partCount): ?VersionedPayloadResult
    {
        $segments = explode('.', $payload);
        $firstSegment = $segments[0];

        if (count($segments) === ($partCount + 1) && $segments[0] === $expectedVersion) {
            $versionedParts = array_slice($segments, 1);
            if (self::allNonEmpty($versionedParts)) {
                return new VersionedPayloadResult(true, $versionedParts);
            }

            return null;
        }

        if ($firstSegment === $expectedVersion) {
            return null;
        }

        if (count($segments) === $partCount && self::allNonEmpty($segments)) {
            return new VersionedPayloadResult(false, $segments);
        }

        return null;
    }

    public static function parseCompact(string $payload, string $expectedVersion): ?CompactPayloadResult
    {
        $parsedPayload = self::parse($payload, $expectedVersion, 4);
        if ($parsedPayload === null) {
            return null;
        }

        [$algorithm, $encodedKeyId, $nonce, $ciphertext] = $parsedPayload->parts;
        $keyId = $encodedKeyId === self::EMPTY_KEY_ID ? null : $encodedKeyId;

        return new CompactPayloadResult($parsedPayload->versioned, $algorithm, $keyId, $nonce, $ciphertext);
    }

    /**
     * @param array<int, string> $segments
     */
    private static function allNonEmpty(array $segments): bool
    {
        return array_all($segments, fn($segment) => !($segment === ''));
    }

    private static function normalizeKeyIdForEncoding(?string $keyId): string
    {
        if ($keyId === null) {
            return self::EMPTY_KEY_ID;
        }

        if ($keyId === '' || str_contains($keyId, '.')) {
            throw new \InvalidArgumentException('Payload key id must be a non-empty dot-safe string.');
        }

        if ($keyId === self::EMPTY_KEY_ID) {
            throw new \InvalidArgumentException(sprintf('Payload key id "%s" is reserved.', self::EMPTY_KEY_ID));
        }

        return $keyId;
    }
}
