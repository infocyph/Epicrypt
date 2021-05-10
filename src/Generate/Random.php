<?php


namespace AbmmHasan\SafeGuard\Generate;


use Exception;

final class Random
{
    /**
     * Generate Secure random string of a given length
     *
     * @param int $length
     * @param string $prefix
     * @param string $postfix
     * @return string
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
            return $prefix .
                substr(
                    str_replace(['+', '/', '='], '', base64_encode(random_bytes($length))),
                    0, $length)
                . $postfix;
        } catch (Exception $e) {
            return '';
        }
    }

    /**
     * Generate Secure random number of given length
     *
     * @param int $length
     * @return int
     */
    public static function number(int $length = 6): int
    {
        try {
            $min = 1 . str_repeat(0, $length - 1);
            $max = str_repeat(9, $length);
            return random_int((int)$min, (int)$max);
        } catch (Exception $e) {
            return 0;
        }
    }

    /**
     * Generate random boolean
     *
     * @return bool
     * @throws Exception
     */
    public static function bool(): bool
    {
        return random_int(0, 1) === 1;
    }
}
