<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class SecurityPolicy
{
    public const string DEFAULT_KEY_ROTATION_HMAC_ALGORITHM = 'sha256';

    public const int MAX_SECURITY_IDENTIFIER_BYTES = 256;

    public const int MIN_SECURITY_SECRET_BYTES = 32;

    public const int PASSWORD_DEFAULT_MEMORY_COST = PASSWORD_ARGON2_DEFAULT_MEMORY_COST;

    public const int PASSWORD_DEFAULT_THREADS = PASSWORD_ARGON2_DEFAULT_THREADS;

    public const int PASSWORD_DEFAULT_TIME_COST = PASSWORD_ARGON2_DEFAULT_TIME_COST;

    public const string SIGNED_URL_VERSION_PARAM = 'ep_v';

    public static function assertHmacSecret(#[\SensitiveParameter] string $secret, string $label): void
    {
        if (strlen($secret) < self::MIN_SECURITY_SECRET_BYTES) {
            throw new ConfigurationException(sprintf(
                '%s must contain at least %d raw bytes.',
                $label,
                self::MIN_SECURITY_SECRET_BYTES,
            ));
        }
    }

    public static function assertIdentifier(string $value, string $label): void
    {
        $length = strlen($value);
        if ($length < 1 || $length > self::MAX_SECURITY_IDENTIFIER_BYTES || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf(
                '%s must be 1..%d bytes and contain no control characters.',
                $label,
                self::MAX_SECURITY_IDENTIFIER_BYTES,
            ));
        }
    }

    public static function assertTtl(int $ttlSeconds, int $maximumSeconds, string $label): void
    {
        if ($ttlSeconds < 1 || $ttlSeconds > $maximumSeconds) {
            throw new ConfigurationException(sprintf('%s must be between 1 and %d seconds.', $label, $maximumSeconds));
        }
    }
}
