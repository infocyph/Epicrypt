<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

/**
 * @internal
 */
final class ContextValue
{
    /**
     * @param array<string, mixed> $context
     * @param \Closure(string): \Throwable $boolExceptionFactory
     * @param \Closure(string): \Throwable $stringExceptionFactory
     * @param \Closure(string): \Throwable $optionalStringExceptionFactory
     * @return array{key_is_binary: bool, nonce_is_binary: bool, aad: string, key_id: ?string}
     */
    public static function baseProtectionFields(
        array $context,
        \Closure $boolExceptionFactory,
        \Closure $stringExceptionFactory,
        \Closure $optionalStringExceptionFactory,
    ): array {
        return [
            'key_is_binary' => self::bool($context, 'key_is_binary', false, $boolExceptionFactory),
            'nonce_is_binary' => self::bool($context, 'nonce_is_binary', false, $boolExceptionFactory),
            'aad' => self::string($context, 'aad', '', $stringExceptionFactory),
            'key_id' => self::optionalNonEmptyString($context, 'key_id', $optionalStringExceptionFactory),
        ];
    }

    /**
     * @param array<string, mixed> $context
     * @param \Closure(string): \Throwable $exceptionFactory
     */
    public static function bool(array $context, string $key, bool $default, \Closure $exceptionFactory): bool
    {
        $value = $context[$key] ?? $default;
        if (!is_bool($value)) {
            throw $exceptionFactory($key);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $context
     * @param \Closure(string): \Throwable $exceptionFactory
     */
    public static function optionalNonEmptyString(array $context, string $key, \Closure $exceptionFactory): ?string
    {
        $value = $context[$key] ?? null;
        if ($value !== null && (!is_string($value) || $value === '')) {
            throw $exceptionFactory($key);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $context
     * @param \Closure(string): \Throwable $exceptionFactory
     */
    public static function string(array $context, string $key, string $default, \Closure $exceptionFactory): string
    {
        $value = $context[$key] ?? $default;
        if (!is_string($value)) {
            throw $exceptionFactory($key);
        }

        return $value;
    }
}
