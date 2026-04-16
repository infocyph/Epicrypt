<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Internal\Base64Url;

final class BinaryCodec
{
    public function decode(string $value): string
    {
        return Base64Url::decode($value);
    }

    public function encode(string $value): string
    {
        return Base64Url::encode($value);
    }
}
