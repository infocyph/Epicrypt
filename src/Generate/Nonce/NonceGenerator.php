<?php

namespace Infocyph\Epicrypt\Generate\Nonce;

use Infocyph\Epicrypt\Internal\Base64Url;

final class NonceGenerator
{
    public function generate(int $length = 24, bool $asBase64Url = true): string
    {
        $nonce = random_bytes($length);

        return $asBase64Url ? Base64Url::encode($nonce) : $nonce;
    }
}
