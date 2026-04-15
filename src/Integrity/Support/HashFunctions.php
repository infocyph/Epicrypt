<?php

namespace Infocyph\Epicrypt\Integrity\Support;

use HashContext;

final class HashFunctions
{
    public static function hash(string $algorithm, string $data, bool $binary = false, array $options = []): string|false
    {
        return hash($algorithm, $data, $binary, $options);
    }

    public static function hash_algos(): array
    {
        return hash_algos();
    }

    public static function hash_copy(HashContext $context): HashContext
    {
        return hash_copy($context);
    }

    public static function hash_file(string $algorithm, string $filename, bool $binary = false, array $options = []): string|false
    {
        return hash_file($algorithm, $filename, $binary, $options);
    }

    public static function hash_final(HashContext $context, bool $binary = false): string
    {
        return hash_final($context, $binary);
    }

    public static function hash_hkdf(
        string $algorithm,
        string $key,
        int $length = 0,
        string $info = '',
        string $salt = '',
    ): string|false {
        return hash_hkdf($algorithm, $key, $length, $info, $salt);
    }

    public static function hash_hmac(string $algorithm, string $data, string $key, bool $binary = false): string|false
    {
        return hash_hmac($algorithm, $data, $key, $binary);
    }

    public static function hash_hmac_algos(): array
    {
        return hash_hmac_algos();
    }

    public static function hash_hmac_file(string $algorithm, string $filename, string $key, bool $binary = false): string|false
    {
        return hash_hmac_file($algorithm, $filename, $key, $binary);
    }

    public static function hash_init(string $algorithm, int $flags = 0, string $key = '', array $options = []): HashContext
    {
        return hash_init($algorithm, $flags, $key, $options);
    }

    public static function hash_pbkdf2(
        string $algorithm,
        string $password,
        string $salt,
        int $iterations,
        int $length = 0,
        bool $binary = false,
    ): string|false {
        return hash_pbkdf2($algorithm, $password, $salt, $iterations, $length, $binary);
    }

    public static function hash_update(HashContext $context, string $data): bool
    {
        return hash_update($context, $data);
    }

    public static function hash_update_file(HashContext $context, string $filename, mixed $streamContext = null): bool
    {
        return hash_update_file($context, $filename, $streamContext);
    }

    /**
     * @param resource $stream
     */
    public static function hash_update_stream(HashContext $context, mixed $stream, int $length = -1): int
    {
        return hash_update_stream($context, $stream, $length);
    }
}
