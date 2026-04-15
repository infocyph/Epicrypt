<?php

namespace Infocyph\Epicrypt\Generate;

use Exception;

final class Random
{
    /**
     * Generate random boolean
     *
     * @throws Exception
     */
    public static function bool(): bool
    {
        return random_int(0, 1) === 1;
    }

    /**
     * Generate Secure random number of given length
     *
     * @throws Exception
     */
    public static function number(int $length = 6): int
    {
        return random_int(
            intval('1' . str_repeat('0', $length - 1)),
            intval(str_repeat('9', $length)),
        );
    }
    /**
     * Generate Secure random string of a given length
     */
    public static function string(int $length = 32, string $prefix = '', string $postfix = ''): string
    {
        try {
            if (!empty($prefix . $postfix)) {
                $length = $length - strlen($prefix . $postfix);
            }
            if ($length < 1) {
                return $prefix . $postfix;
            }
            return $prefix
                . substr(
                    str_replace(
                        ['+', '/', '\\'],
                        '',
                        sodium_bin2base64(random_bytes($length), SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING),
                    ),
                    0,
                    $length,
                )
                . $postfix;
        } catch (Exception) {
            return '';
        }
    }
}
