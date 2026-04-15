<?php

namespace Infocyph\Epicrypt\Password\Support;

final class PasswordFunctions
{
    public static function password_algos(): array
    {
        return password_algos();
    }

    public static function password_get_info(string $hash): array
    {
        return password_get_info($hash);
    }
    public static function password_hash(string $password, string|int|null $algorithm, array $options = []): string
    {
        return password_hash($password, $algorithm, $options);
    }

    public static function password_needs_rehash(string $hash, string|int|null $algorithm, array $options = []): bool
    {
        return password_needs_rehash($hash, $algorithm, $options);
    }

    public static function password_verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
