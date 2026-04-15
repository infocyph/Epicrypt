<?php

namespace Infocyph\Epicrypt\Generate;

use Infocyph\Epicrypt\Internal\Base64Url;

final class SaltGenerator
{
    public function generate(int $length = 16, bool $asBase64Url = true): string
    {
        $salt = random_bytes($length);

        return $asBase64Url ? Base64Url::encode($salt) : $salt;
    }
}
