<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;

/** @internal */
final class JosePolicy
{
    public const int MAX_COMPACT_TOKEN_BYTES = 16 * 1024;

    public const int MAX_JWE_SERIALIZED_BYTES = 16 * 1024 * 1024;

    public const int MAX_JWE_PLAINTEXT_BYTES = 12 * 1024 * 1024;

    public const int MAX_JSON_DEPTH = 16;

    public const int MAX_HEADER_BYTES = 4 * 1024;

    public const int MAX_HEADER_MEMBERS = 64;

    public const int MAX_CLAIM_MEMBERS = 256;

    public const int MAX_DOCUMENT_MEMBERS = 512;

    public const int MAX_PARTICIPANTS = 32;

    public const int MAX_JWK_MEMBERS = 32;

    public const int MAX_JWKS_KEYS = 1_000;

    public const int MAX_KEY_ID_BYTES = 128;

    public static function assertConfiguredMemberCount(array $value, int $maximumMembers, string $label): void
    {
        if (self::memberCount($value, $maximumMembers) > $maximumMembers) {
            throw new ConfigurationException(sprintf('%s contains too many members.', $label));
        }
    }

    public static function assertGeneratedSize(string $value, int $maximumBytes, string $label): void
    {
        if ($value === '' || strlen($value) > $maximumBytes) {
            throw new ConfigurationException(sprintf('%s must be between 1 and %d bytes.', $label, $maximumBytes));
        }
    }

    public static function assertInputSize(
        #[\SensitiveParameter]
        string $value,
        int $maximumBytes,
        string $label,
    ): void {
        if ($value === '' || strlen($value) > $maximumBytes) {
            throw new InvalidTokenException(sprintf('%s size is invalid.', $label));
        }
    }

    /** @param array<mixed> $value */
    public static function assertMemberCount(array $value, int $maximumMembers, string $label): void
    {
        if (self::memberCount($value, $maximumMembers) > $maximumMembers) {
            throw new InvalidTokenException(sprintf('%s contains too many members.', $label));
        }
    }

    public static function isKeyId(string $keyId): bool
    {
        $length = strlen($keyId);

        return $length >= 1
            && $length <= self::MAX_KEY_ID_BYTES
            && preg_match('/\A[A-Za-z0-9_-]+\z/D', $keyId) === 1;
    }

    public static function assertConfiguredKeyId(?string $keyId, string $label): void
    {
        if ($keyId !== null && !self::isKeyId($keyId)) {
            throw new ConfigurationException(sprintf('%s must be a Base64URL-safe identifier of at most %d bytes.', $label, self::MAX_KEY_ID_BYTES));
        }
    }

    public static function assertParticipantCount(int $count, string $label): void
    {
        if ($count < 1 || $count > self::MAX_PARTICIPANTS) {
            throw new ConfigurationException(sprintf('%s requires between 1 and %d participants.', $label, self::MAX_PARTICIPANTS));
        }
    }

    /** @param array<mixed> $value */
    private static function memberCount(array $value, int $stopAfter): int
    {
        $members = 0;
        $pending = [$value];

        while ($pending !== []) {
            $current = array_pop($pending);
            if (!is_array($current)) {
                continue;
            }

            $members += count($current);
            if ($members > $stopAfter) {
                return $members;
            }

            foreach ($current as $member) {
                if (is_array($member)) {
                    $pending[] = $member;
                }
            }
        }

        return $members;
    }
}
