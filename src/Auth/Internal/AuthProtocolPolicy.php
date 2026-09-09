<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;

/**
 * Hard security ceilings shared by Epicrypt authentication protocols.
 *
 * Public server/client policy may impose stricter values, but must never expand
 * untrusted input beyond these limits.
 *
 * @internal
 */
final class AuthProtocolPolicy
{
    public const int MAX_PARAMETERS = 64;
    public const int MAX_AUTH_CLAIMS = 64;
    public const int MAX_COMPACT_TOKEN_BYTES = JosePolicy::MAX_COMPACT_TOKEN_BYTES;
    public const int MAX_JSON_DEPTH = JosePolicy::MAX_JSON_DEPTH;
    public const int MAX_PARAMETER_NAME_BYTES = 128;
    public const int MAX_PARAMETER_VALUE_BYTES = 4_096;
    public const int MAX_ISSUER_BYTES = 2_048;
    public const int MAX_IDENTIFIER_BYTES = 255;
    public const int MAX_REDIRECT_URI_BYTES = 2_048;
    public const int MAX_NONCE_BYTES = 256;
    public const int MAX_SCOPE_COUNT = 64;
    public const int MAX_SCOPE_BYTES = 255;
    public const int MAX_SCOPE_TOTAL_BYTES = 4_096;
    public const int MAX_AUDIENCE_COUNT = 32;
    public const int MAX_AUDIENCE_BYTES = 2_048;
    public const int MAX_AUTHENTICATION_METHOD_COUNT = 16;
    public const int MAX_AUTHENTICATION_METHOD_BYTES = 64;
    public const int MIN_PKCE_VERIFIER_BYTES = 43;
    public const int MAX_PKCE_VERIFIER_BYTES = 128;
    public const int MAX_PERSONAL_TOKEN_ABILITIES = 64;
    public const int MAX_PERSONAL_TOKEN_ABILITY_BYTES = 255;
    public const int MAX_PERSONAL_TOKEN_ABILITY_TOTAL_BYTES = 4_096;
    public const int MAX_PERSONAL_TOKEN_NAME_BYTES = 255;
    public const int MAX_STORE_LIST_RECORDS = 1_000;

    private const string OAUTH_SCOPE_PATTERN = '/\A[\x21\x23-\x5B\x5D-\x7E]+\z/D';
    private const string PKCE_VERIFIER_PATTERN = '/\A[A-Za-z0-9._~-]{43,128}\z/D';
    private const string SHA256_BASE64URL_PATTERN = '/\A[A-Za-z0-9_-]{43}\z/D';

    public static function validParameterName(string $name): bool
    {
        return self::validText($name, self::MAX_PARAMETER_NAME_BYTES);
    }

    public static function validParameterValue(string $value): bool
    {
        return strlen($value) <= self::MAX_PARAMETER_VALUE_BYTES
            && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) !== 1;
    }

    public static function assertText(string $value, int $maximumBytes, string $label): void
    {
        if (!self::validText($value, $maximumBytes)) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    public static function validText(string $value, int $maximumBytes): bool
    {
        return $maximumBytes > 0
            && $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    public static function validSha256Base64Url(string $value): bool
    {
        return preg_match(self::SHA256_BASE64URL_PATTERN, $value) === 1;
    }

    public static function validPkceVerifier(string $value): bool
    {
        return preg_match(self::PKCE_VERIFIER_PATTERN, $value) === 1;
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @return list<string>
     */
    public static function normalizeScopes(array $scopes, string $label): array
    {
        if (!array_is_list($scopes) || count($scopes) > self::MAX_SCOPE_COUNT) {
            throw new ConfigurationException(sprintf('%s must be a bounded list.', $label));
        }

        $seen = [];
        $normalized = [];
        $totalBytes = 0;
        foreach ($scopes as $scope) {
            if (!is_string($scope)
                || strlen($scope) > self::MAX_SCOPE_BYTES
                || preg_match(self::OAUTH_SCOPE_PATTERN, $scope) !== 1
                || isset($seen[$scope])) {
                throw new ConfigurationException(sprintf('%s must contain unique OAuth scope tokens.', $label));
            }
            $totalBytes += strlen($scope) + ($normalized === [] ? 0 : 1);
            if ($totalBytes > self::MAX_SCOPE_TOTAL_BYTES) {
                throw new ConfigurationException(sprintf('%s value is too large.', $label));
            }
            $seen[$scope] = true;
            $normalized[] = $scope;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $audiences
     * @return list<string>
     */
    public static function normalizeAudiences(array $audiences, string $label): array
    {
        return self::normalizeUniqueTextList(
            $audiences,
            self::MAX_AUDIENCE_COUNT,
            self::MAX_AUDIENCE_BYTES,
            $label,
            requireNonEmpty: true,
        );
    }

    /**
     * @param array<array-key, mixed> $methods
     * @return list<string>
     */
    public static function normalizeAuthenticationMethods(array $methods, string $label): array
    {
        return self::normalizeUniqueTextList(
            $methods,
            self::MAX_AUTHENTICATION_METHOD_COUNT,
            self::MAX_AUTHENTICATION_METHOD_BYTES,
            $label,
        );
    }

    /**
     * @param array<array-key, mixed> $abilities
     * @return list<string>
     */
    public static function normalizePersonalTokenAbilities(array $abilities, string $label = 'Personal-token abilities'): array
    {
        if (!array_is_list($abilities) || count($abilities) > self::MAX_PERSONAL_TOKEN_ABILITIES) {
            throw new ConfigurationException(sprintf('%s must be a bounded list.', $label));
        }

        $seen = [];
        $normalized = [];
        $totalBytes = 0;
        foreach ($abilities as $ability) {
            if (!is_string($ability)
                || !self::validText($ability, self::MAX_PERSONAL_TOKEN_ABILITY_BYTES)
                || isset($seen[$ability])) {
                throw new ConfigurationException(sprintf('%s must contain unique bounded strings.', $label));
            }
            $totalBytes += strlen($ability) + ($normalized === [] ? 0 : 1);
            if ($totalBytes > self::MAX_PERSONAL_TOKEN_ABILITY_TOTAL_BYTES) {
                throw new ConfigurationException(sprintf('%s value is too large.', $label));
            }
            $seen[$ability] = true;
            $normalized[] = $ability;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<string>
     */
    private static function normalizeUniqueTextList(
        array $values,
        int $maximumItems,
        int $maximumItemBytes,
        string $label,
        bool $requireNonEmpty = false,
    ): array {
        if (($requireNonEmpty && $values === []) || !array_is_list($values) || count($values) > $maximumItems) {
            throw new ConfigurationException(sprintf('%s must be a bounded list.', $label));
        }

        $seen = [];
        $normalized = [];
        foreach ($values as $value) {
            if (!is_string($value) || !self::validText($value, $maximumItemBytes) || isset($seen[$value])) {
                throw new ConfigurationException(sprintf('%s must contain unique bounded strings.', $label));
            }
            $seen[$value] = true;
            $normalized[] = $value;
        }

        return $normalized;
    }
}
