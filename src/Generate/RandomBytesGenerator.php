<?php

namespace Infocyph\Epicrypt\Generate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\Contract\RandomGeneratorInterface;
use Infocyph\Epicrypt\Internal\Base64Url;

final class RandomBytesGenerator implements RandomGeneratorInterface
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

        $bodyLength = $length - strlen($prefix . $postfix);
        if ($bodyLength <= 0) {
            return $prefix . $postfix;
        }

        $requiredBytes = (int) ceil(($bodyLength * 3) / 4);
        $random = Base64Url::encode($this->bytes($requiredBytes));

        return $prefix . substr($random, 0, $bodyLength) . $postfix;
    }
}
