<?php

use Infocyph\Epicrypt\Generate\Random;
use Infocyph\Epicrypt\PasswordBox\GeneratePassword;

if (!function_exists('generatePassword')) {
    /**
     * Generate password
     *
     * @throws Exception
     */
    function generatePassword(int $length = 9, bool $strong = true): string
    {
        if ($strong) {
            return GeneratePassword::strong($length);
        }
        return GeneratePassword::random($length);
    }
}

if (!function_exists('passwordFromString')) {
    /**
     * Generate random password from given string
     *
     * @throws Exception
     */
    function passwordFromString(string $string): string
    {
        return GeneratePassword::fromString($string);
    }
}

if (!function_exists('randomString')) {
    /**
     * Generate secure random string
     */
    function randomString(int $length = 32, string $prefix = '', string $postfix = ''): string
    {
        return Random::string($length, $prefix, $postfix);
    }
}

if (!function_exists('randomNumber')) {
    /**
     * Generate secure random number
     *
     * @throws Exception
     */
    function randomNumber(int $length = 6): int
    {
        return Random::number($length);
    }
}

if (!function_exists('randomBool')) {
    /**
     * Generate secure random boolean value
     *
     * @throws Exception
     */
    function randomBool(): bool
    {
        return Random::bool();
    }
}
