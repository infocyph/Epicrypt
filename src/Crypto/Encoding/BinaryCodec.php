<?php

namespace Infocyph\Epicrypt\Crypto\Encoding;

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
