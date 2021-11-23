<?php


namespace AbmmHasan\SafeGuard\PasswordBox;


use Exception;

final class GeneratePassword
{
    private static array $combo = [
        'u' => ['A', 'C', 'D', 'E', 'F', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'],
        'l' => ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'],
        'd' => [2, 3, 4, 5, 6, 7, 9],
        's' => ['!', '@', '#', '$', '^', '%', '&', '*', '?', '(', ')', '.', ',', '+', '~', '[', ']', '{', '}', '_', '-', '='],
        'a' => [0, 1, 6, 8, 'B', 'G', 'I', 'i', 'l', 'O', 'o', 'Q']
    ];

    private static array $switch = [
        'm' => ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', ' 4', ' 5', ' 6', ' 7', ' 8', ' 9', ' '],
        'd' => ['4', '8', 'c', '0', '3', 'f', '6', 'h', '9', 'j', 'k', '1', 'm', 'n', '0', 'p', '9', 'r', '5', 't', 'u', 'v', 'w', 'x', 'y', '2', 'o', 'l', '2', 'e', 'a', 's', 'g', '7', 'b', 'i', '_'],
        's1' => ['@', 'b', 'c', 'd', 'e', 'f', 'g', 'h', '!', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '$', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', ':', '9', '-'],
        's2' => ['^', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', ' 3', '4', '5', '6', '7', '8', '9', ' '],
    ];

    /**
     * Generate a random secure password
     *
     * @param int $length
     * @param bool $includeAmbiguous
     * @return string
     * @throws Exception
     */
    public static function strong(int $length = 9, bool $includeAmbiguous = true): string
    {
        if ($length < 8) {
            throw new Exception('Password length should be at-least 8');
        }
        $set = ['u', 'l', 'd', 's', 'a'];
        if (!$includeAmbiguous) {
            unset($set[4]);
        }
        do {
            $password = self::random($length, $set);
        } while (
            !preg_match('/[a-z]+/', $password) ||
            !preg_match('/[A-Z]+/', $password) ||
            !preg_match("/\d/", $password) ||
            !preg_match("/\W+/", $password)
        );
        return $password;
    }

    /**
     * Convert a given string to a secure password for easy memorizing
     *
     * @param string $string
     * @return string
     * @throws Exception
     */
    public static function fromString(string $string): string
    {
        $string = str_split(strtolower($string));
        $converted = [];
        foreach ($string as $letter) {
            $index = array_search($letter, self::$switch['m']);
            $set = array_rand(self::$switch);
            $selected = self::$switch[$set][$index];
            if (ctype_alpha($selected) && random_int(0, 1) === 1) {
                $selected = strtoupper($selected);
            }
            $converted[] = $selected;
        }
        return implode('', $converted);
    }

    /**
     * Generate a random password of a given length and defined Set
     *
     * @param int $length
     * @param array $type
     * @return string
     * @throws Exception
     */
    public static function random(int $length = 9, array $type = ['u', 'l', 'd', 's', 'a']): string
    {
        $sets = $password = [];
        foreach (self::$combo as $group => $items) {
            if (!in_array($group, $type)) {
                continue;
            }
            shuffle($items);
            $sets = array_merge($sets, $items);
        }
        if (empty($sets)) {
            throw new Exception('No detectable type found!');
        }
        for ($i = 0; $i < $length; $i++) {
            $password[] = $sets[array_rand($sets)];
        }
        return implode('', $password);
    }
}
