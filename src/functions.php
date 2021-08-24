<?php

use AbmmHasan\SafeGuard\Generate\Password;
use AbmmHasan\SafeGuard\Generate\Random;

if (!function_exists('getDHPrime')) {
    /**
     * Generate a prime number using OpenSSL DH
     *
     * @param int $privateKeyBits
     * @return string
     * @throws Exception
     */
    function getDHPrime(int $privateKeyBits = 2048): string
    {
        if ($privateKeyBits < 384) {
            throw new Exception('Invalid private key bit size! Should be at-least 384.');
        }

        return openssl_pkey_get_details(openssl_pkey_new([
            'private_key_bits' => $privateKeyBits,
            'private_key_type' => OPENSSL_KEYTYPE_DH
        ]))['dh']['p'];
    }
}

if (!function_exists('generatePassword')) {
    /**
     * Generate password
     *
     * @param int $length
     * @param bool / epoch time $from
     * @return string
     * @throws Exception
     */
    function generatePassword(int $length = 9, $strong = true): string
    {
        if ($strong) {
            return Password::strong($length);
        }
        return Password::random($length);
    }
}

if (!function_exists('passwordFromString')) {
    /**
     * Generate random password from given string
     *
     * @param string $string
     * @return string
     * @throws Exception
     */
    function passwordFromString(string $string): string
    {
        return Password::fromString($string);
    }
}

if (!function_exists('randomString')) {
    /**
     * Generate secure random string
     *
     * @param int $length
     * @param string $prefix
     * @param string $postfix
     * @return string
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
     * @param int $length
     * @return int
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
     * @return bool
     * @throws Exception
     */
    function randomBool(): bool
    {
        return Random::bool();
    }
}
