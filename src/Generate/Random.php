<?php

namespace Infocyph\Epicrypt\Generate;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class Random
{
    public static function bool(): bool
    {
        return random_int(0, 1) === 1;
    }

    public static function number(int $length = 6): int
    {
        if ($length < 1) {
            throw new ConfigurationException('Number length must be at least 1.');
        }
        if ($length > 18) {
            throw new ConfigurationException('Number length must be 18 or less.');
        }

        return random_int(
            (int) ('1' . str_repeat('0', $length - 1)),
            (int) str_repeat('9', $length),
        );
    }

    public static function string(int $length = 32, string $prefix = '', string $postfix = ''): string
    {
        return new RandomBytesGenerator()->string($length, $prefix, $postfix);
    }
}
