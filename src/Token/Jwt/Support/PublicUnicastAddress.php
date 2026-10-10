<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

/** @internal Shared public-unicast destination policy for remote JOSE resources. */
final class PublicUnicastAddress
{
    public static function allows(string $address): bool
    {
        $packed = inet_pton($address);
        if (!is_string($packed)) {
            return false;
        }

        if (strlen($packed) === 16) {
            if (substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
                $mapped = inet_ntop(substr($packed, 12));

                return is_string($mapped) && self::allows($mapped);
            }

            return ord($packed[0]) !== 0xff
                && filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false;
        }

        return strlen($packed) === 4
            && filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false
            && (ord($packed[0]) < 224 || ord($packed[0]) > 239);
    }
}
