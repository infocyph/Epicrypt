<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class RandomBytesGenerator
{
    public function bytes(int $length): string
    {
        if ($length < 1) {
            throw new ConfigurationException('Length must be at least 1 byte.');
        }

        return random_bytes($length);
    }

    public function string(int $length, string $prefix = '', string $postfix = ''): string
    {
        if ($length < 1) {
            throw new ConfigurationException('Length must be at least 1.');
        }

        $affixLength = strlen($prefix) + strlen($postfix);
        if ($affixLength >= $length) {
            throw new ConfigurationException('Prefix and postfix must leave room for at least one random character.');
        }

        $bodyLength = $length - $affixLength;

        $requiredBytes = (int) ceil(($bodyLength * 3) / 4);
        $random = Base64Url::encode($this->bytes($requiredBytes));

        return $prefix . substr($random, 0, $bodyLength) . $postfix;
    }
}
