<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class Base64Url
{
    public static function decode(string $data): string
    {
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new ConfigurationException('Invalid base64url data.');
        }

        return $decoded;
    }

    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
