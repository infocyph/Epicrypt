<?php

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class Json
{
    /**
     * @return array<string, mixed>
     */
    public static function decodeToArray(string $json): array
    {
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($decoded)) {
            throw new ConfigurationException('JSON payload must decode to an object.');
        }

        return $decoded;
    }
    /**
     * @param array<string, mixed> $payload
     */
    public static function encode(array $payload): string
    {
        $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        if (! is_string($json)) {
            throw new ConfigurationException('JSON encoding failed.');
        }

        return $json;
    }
}
